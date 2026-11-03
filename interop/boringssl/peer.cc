// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Independent TLS 1.3 server peer built on BoringSSL, for uTLS interop tests:
// real zlib certificate compression (RFC 8879, algorithm 1) and ALPS.
//
//   peer -cert cert.pem -key key.pem [-zlib] [-alps proto=settingshex]
//        [-alps-new] [-alpn h2,http/1.1]
//
// It listens on 127.0.0.1 (ephemeral port, printed as "PORT n"), serves
// connections until killed, and after each handshake sends one line of
// application data describing what was negotiated:
//   "version=<hex> alpn=<proto> alps=<client settings hex|-> compressed=<n>"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <string>
#include <vector>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>

static int g_compressed = 0;
static std::vector<uint8_t> g_alpn_wire;
static std::string g_alps_proto;
static std::vector<uint8_t> g_alps_settings;
static bool g_alps_new = false;

static int zlib_compress(SSL *ssl, CBB *out, const uint8_t *in, size_t in_len) {
  uLongf n = compressBound(in_len);
  std::vector<uint8_t> buf(n);
  if (compress2(buf.data(), &n, in, in_len, 6) != Z_OK) return 0;
  g_compressed++;
  return CBB_add_bytes(out, buf.data(), n);
}

static int alpn_select(SSL *ssl, const uint8_t **out, uint8_t *out_len,
                       const uint8_t *in, unsigned in_len, void *arg) {
  // Server preference order: first of ours the client offered.
  for (size_t i = 0; i < g_alpn_wire.size(); i += 1 + g_alpn_wire[i]) {
    for (unsigned j = 0; j < in_len; j += 1 + in[j]) {
      if (in[j] == g_alpn_wire[i] && memcmp(in + j + 1, &g_alpn_wire[i + 1], in[j]) == 0) {
        *out = in + j + 1;
        *out_len = in[j];
        return SSL_TLSEXT_ERR_OK;
      }
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static std::vector<uint8_t> unhex(const char *s) {
  std::vector<uint8_t> v;
  for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
    unsigned b;
    sscanf(s + i, "%2x", &b);
    v.push_back((uint8_t)b);
  }
  return v;
}

int main(int argc, char **argv) {
  const char *cert = nullptr, *key = nullptr;
  bool zlib = false;
  std::string alpn = "h2,http/1.1";
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "-cert" && i + 1 < argc) cert = argv[++i];
    else if (a == "-key" && i + 1 < argc) key = argv[++i];
    else if (a == "-zlib") zlib = true;
    else if (a == "-alps-new") g_alps_new = true;
    else if (a == "-alpn" && i + 1 < argc) alpn = argv[++i];
    else if (a == "-alps" && i + 1 < argc) {
      std::string v = argv[++i];
      size_t eq = v.find('=');
      g_alps_proto = v.substr(0, eq);
      g_alps_settings = unhex(v.substr(eq + 1).c_str());
    } else { fprintf(stderr, "bad arg %s\n", a.c_str()); return 2; }
  }
  size_t start = 0;
  while (start <= alpn.size()) {
    size_t c = alpn.find(',', start);
    std::string p = alpn.substr(start, c == std::string::npos ? std::string::npos : c - start);
    g_alpn_wire.push_back((uint8_t)p.size());
    g_alpn_wire.insert(g_alpn_wire.end(), p.begin(), p.end());
    if (c == std::string::npos) break;
    start = c + 1;
  }
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  if (!SSL_CTX_use_certificate_chain_file(ctx, cert) ||
      !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  if (zlib && !SSL_CTX_add_cert_compression_alg(ctx, 1, zlib_compress, nullptr)) return 1;
  SSL_CTX_set_alpn_select_cb(ctx, alpn_select, nullptr);

  int ln = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa = {};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(ln, (sockaddr *)&sa, sizeof(sa)) != 0 || listen(ln, 16) != 0) { perror("listen"); return 1; }
  socklen_t sl = sizeof(sa);
  getsockname(ln, (sockaddr *)&sa, &sl);
  printf("PORT %d\n", ntohs(sa.sin_port));
  fflush(stdout);
  for (;;) {
    int fd = accept(ln, nullptr, nullptr);
    if (fd < 0) continue;
    g_compressed = 0;
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (!g_alps_proto.empty()) {
      SSL_set_alps_use_new_codepoint(ssl, g_alps_new ? 1 : 0);
      SSL_add_application_settings(ssl, (const uint8_t *)g_alps_proto.data(), g_alps_proto.size(),
                                   g_alps_settings.data(), g_alps_settings.size());
    }
    if (SSL_accept(ssl) == 1) {
      const uint8_t *p; unsigned plen;
      SSL_get0_alpn_selected(ssl, &p, &plen);
      const uint8_t *s; size_t slen;
      SSL_get0_peer_application_settings(ssl, &s, &slen);
      std::string hex = SSL_has_application_settings(ssl) ? "" : "-";
      for (size_t i = 0; SSL_has_application_settings(ssl) && i < slen; i++) {
        char b[3]; snprintf(b, 3, "%02x", s[i]); hex += b;
      }
      if (hex.empty()) hex = "empty";
      char line[512];
      snprintf(line, sizeof line, "version=%x alpn=%.*s alps=%s compressed=%d\n",
               SSL_version(ssl), (int)plen, (const char *)p, hex.c_str(), g_compressed);
      SSL_write(ssl, line, strlen(line));
      char buf[64];
      SSL_read(ssl, buf, sizeof buf);  // wait for the client to finish
    } else {
      ERR_print_errors_fp(stderr);
    }
    SSL_free(ssl);
    close(fd);
  }
}
