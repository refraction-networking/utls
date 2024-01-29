//go:build !wasm && !wasi && !wasip1 && !wasip2

package tls

import (
	"context"
	"errors"
	"fmt"
)

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if ctx.Done() != nil {
		// Start the "interrupter" goroutine, if this context might be canceled.
		// (The background context cannot).
		//
		// The interrupter goroutine waits for the input context to be done and
		// closes the connection if this happens before the function returns.
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the handshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	if c.quic != nil {
		if c.handshakeErr == nil {
			c.quicHandshakeComplete()
			// Provide the 1-RTT read secret now that the handshake is complete.
			// The QUIC layer MUST NOT decrypt 1-RTT packets prior to completing
			// the handshake (RFC 9001, Section 5.7).
			c.quicSetReadSecret(QUICEncryptionLevelApplication, c.cipherSuite, c.in.trafficSecret)
		} else {
			var a alert
			c.out.Lock()
			if !errors.As(c.out.err, &a) {
				a = alertInternalError
			}
			c.out.Unlock()
			// Return an error which wraps both the handshake error and
			// any alert error we may have sent, or alertInternalError
			// if we didn't send an alert.
			// Truncate the text of the alert to 0 characters.
			c.handshakeErr = fmt.Errorf("%w%.0w", c.handshakeErr, AlertError(a))
		}
		close(c.quic.blockedc)
		close(c.quic.signalc)
	}

	return c.handshakeErr
}
