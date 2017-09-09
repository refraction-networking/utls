# uTLS
[![Build Status](https://travis-ci.org/refraction-networking/utls.svg?branch=master)](https://travis-ci.org/refraction-networking/utls)
[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/refraction-networking/utls#UConn)
## Low-level access to handshake
* Read/write access to all bits of client hello message.  
* Read access to fields of ClientHandshakeState, which, among other things, includes ServerHello and MasterSecret.
* Read keystream. Can be used to "write" something in ciphertext.
## ClientHello fingerprinting resistance
Golang's ClientHello has a very unique fingerprint, which especially sticks out on mobile clients,
where Golang is not too popular yet.
Some members of anti-censorship community are concerned that their tools could be trivially blocked based on
ClientHello with relatively small collateral damage. There are multiple solutions to this issue.
### Randomized handshake
This package can be used to generate randomized ClientHello.
Provides a moving target without any compatibility or parrot-is-dead attack risks.  
**Feedback about implementation details of randomized handshake is extremely appreciated.**
### Parroting
This package can be used to parrot ClientHello of popular browsers.
There are some caveats to this parroting:
* We are forced to offer ciphersuites and tls extensions that are not supported by crypto/tls.
This is not a problem, if you fully control the server and turn unsupported things off on server side.
* Parroting could be imperfect, and there is no parroting beyond ClientHello.
#### Compatibility risks of available parrots

| Parrot        | Ciphers* | Signature* | Unsupported extensions |
| ------------- | -------- | ---------- | ---------------------- |
| Android 5.1   | low      | very low   | None                   |
| Android 6.0   | low      | very low   | None                   |
| Chrome 58     | no       | low        | ChannelID              |
| Firefox 55    | very low | low        | None                   |

\* Denotes very rough guesstimate of likelihood that unsupported things will get echoed back by the server in the wild,
*visibly breaking the connection*.  


#### Parrots FAQ
> Does it really look like, say, Google Chrome with all the [GREASE](https://tools.ietf.org/html/draft-davidben-tls-grease-01) and stuff?

It LGTM, but please open up Wireshark and check. If you see something — [say something](issues).

> Aren't there side channels? Everybody knows that the ~~bird is a word~~[parrot is dead](https://people.cs.umass.edu/~amir/papers/parrot.pdf)

There sure are. If you found one that approaches practicality at line speed — [please tell us](issues).

#### Things to implement in Golang to make parrots better
 * Extended ChannelID extensions
 * Enable sha512 and sha224 hashes by default
 * Implement RSA PSS signature algorithms
 * In general, any modern crypto is likely to be useful going forward.
### Custom Handshake
It is possible to create custom handshake by
1) Use `HelloCustom` as an argument for `UClient()` to get empty config
2) Fill tls header fields: UConn.Hello.{Random, CipherSuites, CompressionMethods}, if needed, or stick to defaults.
3) Configure and add various [TLS Extensions](u_tls_extensions.go) to UConn.Extensions: they will be marshaled in order.
4) Set Session and SessionCache, as needed.

If you need to manually control all the bytes on the wire(certainly not recommended!),
you can set UConn.HandshakeStateBuilt = true, and marshal clientHello into UConn.HandshakeState.Hello.raw yourself.
In this case you will be responsible for modifying other parts of Config and ClientHelloMsg to reflect your setup.
## Fake Session Tickets
Set of provided functions is likely to change, as use-cases aren't fully worked out yet.
Currently, there is a simple function to set session ticket to any desired state:

```Golang
// If you want you session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionState(session *ClientSessionState)
```

Note that session tickets (fake ones or otherwise) are not reused.  
To reuse tickets, create a shared cache and set it on current and further configs:

```Golang
// If you want you session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionCache(cache ClientSessionCache)
```

## Usage

Find other examples [here](examples/examples.go). 

For a reference, here's how default "crypto/tls" is used:
```Golang
    config := tls.Config{ServerName: "www.google.com"}
    dialConn, err := net.Dial("tcp", "172.217.11.46:443")
    if err != nil {
        fmt.Printf("net.Dial() failed: %+v\n", err)
        return
    }
    tlsConn := tls.Client(dialConn, &config)
    err = tlsConn.Handshake()
    if err != nil {
    fmt.Printf("tlsConn.Handshake() error: %+v", err)
        return
    }
```
Now, if you want to use uTLS, simply substitute `tlsConn := tls.Client(dialConn, &config)`
with `tlsConn := utls.UClient(dialConn, &config, clientHelloID)`
where clientHelloID is one of the following:

1. ```utls.HelloRandomized``` adds/reorders extensions, ciphersuites, etc. randomly.  
`HelloRandomized` adds ALPN in 50% of cases, you may want to use `HelloRandomizedALPN` or
`HelloRandomizedNoALPN` to choose specific behavior explicitly, as ALPN might affect application layer.
2. ```utls.HelloGolang```
    HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
    overwrite your changes to Hello(Config, Session are fine).
    You might want to call BuildHandshakeState() before applying any changes.
    UConn.Extensions will be completely ignored.
3. ```utls.HelloCustom```
will prepare ClientHello with empty uconn.Extensions so you can fill it with TLSExtension's manually.
4. The rest will will parrot given browser.
	* `utls.HelloChrome_Auto`- parrots recommended(latest) Google Chrome version
	* `utls.HelloChrome_58` - parrots Google Chrome 58
	* `utls.HelloFirefox_Auto` - parrots recommended(latest) Firefox version
	* `utls.HelloFirefox_55` - parrots Firefox 55
	* `utls.HelloAndroid_Auto` 
	* `utls.HelloAndroid_6_0_Browser`
	* `utls.HelloAndroid_5_1_Browser`
	
#### Customizing handshake

Before doing `Handshake()` you can also set fake session ticket, set clientHello or change uconn in other ways:
```Golang
    cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
        130, 131}
    tlsConn.SetClientRandom(cRandom)
    masterSecret := make([]byte, 48)
    copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

    // Create a session ticket that wasn't actually issued by the server.
    sessionState := utls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        masterSecret,
        nil, nil)
    tlsConn.SetSessionState(sessionState)
```

Here's an [example](https://github.com/sergeyfrolov/gotapdance/blob/db4336aceafe7a971e171f7cd913a0eed6a5ff50/tapdance/conn_raw.go#L275-L292) of how one could generate randomized ClientHello, modify generated ciphersuites a bit, and proceed with the handshake.

#### Disclamer
This is not an official Google product.
