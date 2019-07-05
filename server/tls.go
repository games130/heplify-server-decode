package input

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/games130/cert"
	"github.com/games130/logp"
)

func (h *HEPInput) serveTLS(addr string) {
	ta, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		logp.Critical("%v", err)
	}

	ln, err := net.ListenTCP("tcp", ta)
	if err != nil {
		logp.Critical("%v", err)
	}

	ca, err := cert.NewCertificateAuthority("heplify-server")
	if err != nil {
		logp.Critical("%v", err)
	}

	var wg sync.WaitGroup

	for {
		select {
		case <-h.quitTLS:
			logp.Info("stopping TLS listener on %s", ln.Addr())
			ln.Close()
			wg.Wait()
			close(h.exitedTLS)
			return
		default:
			ln.SetDeadline(time.Now().Add(1e9))
			conn, err := ln.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				logp.Err("failed to accept TLS connection: %v", err.Error())
			}
			logp.Info("new TLS connection %s -> %s", conn.RemoteAddr(), conn.LocalAddr())
			wg.Add(1)
			go func() {
				h.handleTLS(tls.Server(conn, &tls.Config{GetCertificate: ca.GetCertificate}))
				wg.Done()
			}()
		}
	}
}

func (h *HEPInput) handleTLS(c net.Conn) {
	defer func() {
		logp.Info("closing TLS connection from %s", c.RemoteAddr())
		c.Close()
	}()

	for {
		select {
		case <-h.quitTLS:
			return
		default:
		}

		c.SetReadDeadline(time.Now().Add(1e9))
		buf := h.buffer.Get().([]byte)
		n, err := c.Read(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			} else {
				return
			}
		} else if n > maxPktLen {
			logp.Warn("received too big packet with %d bytes", n)
			continue
		}
		h.inputCh <- buf[:n]
	}
}
