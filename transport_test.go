// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportHTTP(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
		want string
	}{
		{"http1", false, "HTTP/1.1"},
		{"http2", true, "HTTP/2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, r.Proto)
			}))
			srv.EnableHTTP2 = tc.h2
			srv.StartTLS()
			defer srv.Close()

			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())

			rt := &Transport{
				ClientHelloID: HelloChrome_Auto,
				Config:        &tls.Config{RootCAs: roots, ServerName: "example.com"},
			}
			req, _ := http.NewRequest("GET", srv.URL, nil)
			// httptest serves on 127.0.0.1 with a cert for example.com/127.0.0.1;
			// force the SNI/host verification to the cert's name.
			req.Host = "example.com"
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tc.want {
				t.Errorf("proto = %q, want %q", body, tc.want)
			}
		})
	}
}
