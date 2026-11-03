// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// FragmentOptions controls how the first ClientHello is written to the
// transport. Fragmentation never changes the handshake transcript: TLS
// receivers reassemble handshake messages across records, and TCP receivers
// reassemble segments. Only the first ClientHello is affected (not a second
// ClientHello after HelloRetryRequest, and nothing after it).
type FragmentOptions struct {
	// Records splits the ClientHello handshake message into several TLS
	// records (each with its own 5-byte header) at the split points.
	Records bool
	// Segments writes each piece with a separate Write on the net.Conn. On a
	// TCP connection with TCP_NODELAY (Go's default) each Write normally leaves
	// as its own segment; this is best-effort, as the kernel may coalesce.
	Segments bool
	// SplitAtSNI places a split point in the middle of the server_name host
	// name. The handshake fails before anything is written if the ClientHello
	// has no server_name (IP literal or empty ServerName).
	SplitAtSNI bool
	// MaxPieceSize additionally splits so no piece is larger than this many
	// bytes (record payload bytes with Records, raw bytes otherwise). 0 means
	// no size limit.
	MaxPieceSize int
	// Delay is slept between Writes (Segments only). At most one second.
	Delay time.Duration
}

func (o *FragmentOptions) validate() error {
	switch {
	case !o.Records && !o.Segments:
		return errors.New("utls: FragmentOptions needs Records and/or Segments")
	case !o.SplitAtSNI && o.MaxPieceSize == 0:
		return errors.New("utls: FragmentOptions needs SplitAtSNI and/or MaxPieceSize")
	case o.MaxPieceSize < 0:
		return errors.New("utls: negative MaxPieceSize")
	case o.Delay < 0 || o.Delay > time.Second:
		return errors.New("utls: fragment Delay must be between 0 and 1s")
	case o.Delay > 0 && !o.Segments:
		return errors.New("utls: fragment Delay requires Segments")
	}
	return nil
}

// SetFragmentation sets how the first ClientHello is written. It must be called
// before the handshake. It has no effect on QUIC connections (which reject it).
func (u *UConn) SetFragmentation(o FragmentOptions) error {
	if err := o.validate(); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.started {
		return errors.New("utls: cannot set fragmentation after the handshake started")
	}
	if u.Conn.quic != nil {
		return errors.New("utls: fragmentation does not apply to QUIC")
	}
	u.fragment = &o
	return nil
}

// uFragmentPending reports whether the next record write must go through
// writeFragmented. It is called with c.out held.
func (c *Conn) uFragmentPending() bool {
	return c.uconn != nil && c.uconn.fragment != nil
}

// writeFragmented writes the record data (the first record of the first
// ClientHello) according to the fragmentation options, then disarms them. It
// is called from Conn.write with c.out held. It returns len(data) on success.
func (u *UConn) writeFragmented(w net.Conn, data []byte) (int, error) {
	o := u.fragment
	u.fragment = nil
	if len(data) < 6 || data[0] != byte(recordTypeHandshake) || data[5] != typeClientHello {
		return w.Write(data) // not a ClientHello record; nothing to do
	}
	body := data[recordHeaderLen:]
	var points []int // split offsets within body
	if o.SplitAtSNI {
		start, end, ok := sniHostRange(body)
		if !ok || end-start < 2 {
			return 0, errors.New("utls: fragmentation: ClientHello has no server_name to split")
		}
		points = append(points, start+(end-start)/2)
	}
	unit := len(body)
	if !o.Records {
		unit = len(data)
		for i := range points {
			points[i] += recordHeaderLen
		}
	}
	if o.MaxPieceSize > 0 {
		for p := o.MaxPieceSize; p < unit; p += o.MaxPieceSize {
			points = append(points, p)
		}
	}
	slices.Sort(points)
	points = slices.Compact(points)

	var pieces [][]byte
	src := data
	if o.Records {
		src = body
	}
	prev := 0
	for _, p := range append(points, len(src)) {
		if p > prev && p <= len(src) {
			pieces = append(pieces, src[prev:p])
			prev = p
		}
	}
	if o.Records {
		for i, p := range pieces {
			rec := make([]byte, recordHeaderLen, recordHeaderLen+len(p))
			copy(rec, data[:3]) // type and legacy record version as sent
			rec[3], rec[4] = byte(len(p)>>8), byte(len(p))
			pieces[i] = append(rec, p...)
		}
	}
	if !o.Segments {
		if _, err := w.Write(slices.Concat(pieces...)); err != nil {
			return 0, err
		}
		return len(data), nil
	}
	for i, p := range pieces {
		if i > 0 && o.Delay > 0 {
			time.Sleep(o.Delay)
		}
		if _, err := w.Write(p); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

// sniHostRange returns the [start, end) offsets of the first server_name host
// name within a ClientHello handshake message (which may be truncated after
// the extensions it needs).
func sniHostRange(msg []byte) (int, int, bool) {
	s := cryptobyte.String(msg)
	var typ uint8
	var body cryptobyte.String
	if !s.ReadUint8(&typ) || typ != typeClientHello || !s.Skip(3) {
		return 0, 0, false
	}
	body = s
	var sid, suites, comp, exts cryptobyte.String
	if !body.Skip(2+32) || !body.ReadUint8LengthPrefixed(&sid) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&comp) || !body.ReadUint16LengthPrefixed(&exts) {
		return 0, 0, false
	}
	for !exts.Empty() {
		var id uint16
		var ext cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&ext) {
			return 0, 0, false
		}
		if id != extensionServerName {
			continue
		}
		var list cryptobyte.String
		var nameType uint8
		var host cryptobyte.String
		if !ext.ReadUint16LengthPrefixed(&list) || !list.ReadUint8(&nameType) || nameType != 0 ||
			!list.ReadUint16LengthPrefixed(&host) || len(host) == 0 {
			return 0, 0, false
		}
		// host aliases msg, so its offset follows from the capacities.
		start := cap(msg) - cap(host)
		return start, start + len(host), true
	}
	return 0, 0, false
}
