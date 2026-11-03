// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command capture records browser ClientHellos for fixture provenance.
//
//	go run ./interop/capture PORT OUTPREFIX
//
// It listens on 127.0.0.1:PORT for up to 60 seconds and, for each of up to
// three connections, writes the first TLS record as hex to OUTPREFIX.N.hex and
// closes the connection. It never answers the handshake.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: capture PORT OUTPREFIX")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("listening", ln.Addr())
	deadline := time.Now().Add(60 * time.Second)
	n := 0
	for time.Now().Before(deadline) && n < 3 {
		ln.(*net.TCPListener).SetDeadline(deadline)
		c, err := ln.Accept()
		if err != nil {
			break
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err == nil && hdr[0] == 22 {
			body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			if _, err := io.ReadFull(c, body); err == nil {
				name := fmt.Sprintf("%s.%d.hex", os.Args[2], n)
				if err := os.WriteFile(name, []byte(hex.EncodeToString(append(hdr, body...))+"\n"), 0o644); err != nil {
					fmt.Fprintln(os.Stderr, err)
				} else {
					fmt.Println("wrote", name)
				}
				n++
			}
		}
		c.Close()
	}
}
