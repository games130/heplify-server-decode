package input

import (
	"net"
	"time"

	"github.com/games130/logp"
)

func (h *HEPInput) serveUDP(addr string) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logp.Critical("%v", err)
	}

	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		logp.Critical("%v", err)
	}
	defer func() {
		logp.Info("stopping UDP listener on %s", uc.LocalAddr())
		uc.Close()
	}()

	for {
		select {
		case <-h.quitUDP:
			h.quitUDP <- true
			return
		default:
		}
		uc.SetReadDeadline(time.Now().Add(1e9))
		buf := h.buffer.Get().([]byte)
		n, err := uc.Read(buf)
		if err != nil {
			continue
		} else if n > maxPktLen {
			logp.Warn("received too big packet with %d bytes", n)
			continue
		}
		h.inputCh <- buf[:n]
	}
}
