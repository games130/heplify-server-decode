package input

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"context"

	proto "github.com/games130/heplify-server-metric/proto"
	"github.com/micro/go-plugins/broker/nats"
	"github.com/games130/logp"
	"github.com/games130/heplify-server-decode/config"
	"github.com/games130/heplify-server-decode/decoder"
	"github.com/games130/heplify-server-decode/metric"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/broker"
	"github.com/micro/go-log"
)

type HEPInput struct {
	inputCh   chan []byte
	wg        *sync.WaitGroup
	buffer    *sync.Pool
	exitedTCP chan bool
	exitedTLS chan bool
	quitUDP   chan bool
	quitTCP   chan bool
	quitTLS   chan bool
	quit      chan bool
	usePM     bool
	service   micro.Service
	pub1	  micro.Publisher
}

type HEPStats struct {
	DupCount uint64
	ErrCount uint64
	HEPCount uint64
	PktCount uint64
}

const maxPktLen = 8192

func NewHEPInput() *HEPInput {
	h := &HEPInput{
		inputCh:   make(chan []byte, 40000),
		buffer:    &sync.Pool{New: func() interface{} { return make([]byte, maxPktLen) }},
		wg:        &sync.WaitGroup{},
		quit:      make(chan bool),
		quitUDP:   make(chan bool),
		quitTCP:   make(chan bool),
		quitTLS:   make(chan bool),
		exitedTCP: make(chan bool),
		exitedTLS: make(chan bool),
	}


	b := nats.NewBroker(
		broker.Addrs("172.17.0.3:4222"),
	)
	// create a service
	h.service = micro.NewService(
		micro.Name("go.micro.cli.metric"),
		micro.Broker(b),
	)
	// parse command line
	h.service.Init()
	// create publisher
	h.pub1 = micro.NewPublisher("heplify.server.metric.1", h.service.Client())
	
	
	if len(config.Setting.PromAddr) > 2 {
		h.usePM = true
		h.promCh = make(chan *decoder.HEP, 40000)
	}

	return h
}

func (h *HEPInput) Run() {
	logp.Info("--------------------------------server---run---------------------------------")
	for n := 0; n < runtime.NumCPU(); n++ {
		h.wg.Add(1)
		go h.hepWorker()
	}

	logp.Info("start %s with %#v\n", config.Version, config.Setting)

	if config.Setting.HEPAddr != "" {
		go h.serveUDP(config.Setting.HEPAddr)
	}
	if config.Setting.HEPTCPAddr != "" {
		go h.serveTCP(config.Setting.HEPTCPAddr)
	}
	if config.Setting.HEPTLSAddr != "" {
		go h.serveTLS(config.Setting.HEPTLSAddr)
	}
	h.wg.Wait()
}

func (h *HEPInput) End() {
	logp.Info("stopping heplify-server...")

	if config.Setting.HEPAddr != "" {
		h.quitUDP <- true
		<-h.quitUDP
	}
	if config.Setting.HEPTCPAddr != "" {
		close(h.quitTCP)
		<-h.exitedTCP
	}
	if config.Setting.HEPTLSAddr != "" {
		close(h.quitTLS)
		<-h.exitedTLS
	}

	h.quit <- true
	<-h.quit

	logp.Info("heplify-server has been stopped")
}

func (h *HEPInput) hepWorker() {
	lastWarn := time.Now()
	msg := h.buffer.Get().([]byte)

	for {
		h.buffer.Put(msg[:maxPktLen])
		select {
		case <-h.quit:
			h.quit <- true
			h.wg.Done()
			return
		case msg = <-h.inputCh:
			hepPkt, err := decoder.DecodeHEP(msg)

			if h.usePM {
				tStr,_ := hepPkt.Timestamp.MarshalText()
				ev := &proto.Event{
					Version: 		hepPkt.Version,
					Protocol:		hepPkt.Protocol,
					SrcIP:			hepPkt.SrcIP,
					DstIP:			hepPkt.DstIP,
					SrcPort:		hepPkt.SrcPort,
					DstPort:		hepPkt.DstPort,
					Tsec:			hepPkt.Tsec,
					Tmsec:			hepPkt.Tmsec,
					ProtoType:		hepPkt.ProtoType,
					NodeID:			hepPkt.NodeID,
					NodePW:			hepPkt.NodePW,
					Payload:		hepPkt.Payload,
					CID:			hepPkt.CID,
					Vlan:			hepPkt.Vlan,
					CseqMethod:		hepPkt.SIP.CseqMethod,
					FirstMethod:		hepPkt.SIP.FirstMethod,
					CallID:			hepPkt.SIP.CallID,
					FromUser:		hepPkt.SIP.FromUser,
					Expires:		hepPkt.SIP.Expires,
					ReasonVal:		hepPkt.SIP.ReasonVal,
					RTPStatVal:		hepPkt.SIP.RTPStatVal,
					ToUser:			hepPkt.SIP.ToUser,
					ProtoString:		hepPkt.ProtoString,
					Timestamp:		string(tStr),
					HostTag:		hepPkt.HostTag,
					NodeName:		hepPkt.NodeName,
				}
			
				log.Logf("publishing %+v\n", hepPkt.CID)
				err := h.pub1.Publish(context.Background(), ev)
				if err != nil {
					log.Logf("error publishing: %v", err)
				}
			}
		}
	}
}
