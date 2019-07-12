package input

import (
	"runtime"
	"sync"
	"sync/atomic"
	"context"
	//"time"

	proto "github.com/games130/heplify-server-metric/proto"
	"github.com/micro/go-plugins/broker/nats"
	"github.com/games130/logp"
	"github.com/games130/heplify-server-decode/config"
	"github.com/games130/heplify-server-decode/decoder"
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
	stats     HEPStats
}

type HEPStats struct {
	HEPCount 		uint64
	INVITECount		uint64
	REGISTERCount	uint64
	BYECount		uint64
	PRACKCount		uint64
	180Count uint64
	183Count uint64
	200Count uint64
	400Count uint64
	404Count uint64
	406Count uint64
	408Count uint64
	416Count uint64
	420Count uint64
	422Count uint64
	480Count uint64
	481Count uint64
	484Count uint64
	485Count uint64
	488Count uint64
	500Count uint64
	502Count uint64
	503Count uint64
	504Count uint64
	603Count uint64
	604Count uint64
	OtherCount uint64
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
	SIPMap = make(map[string]int64)


	b := nats.NewBroker(
		broker.Addrs(config.Setting.BrokerAddr),
	)
	// create a service
	h.service = micro.NewService(
		micro.Name("go.micro.cli.metric"),
		micro.Broker(b),
	)
	// parse command line
	h.service.Init()
	// create publisher
	h.pub1 = micro.NewPublisher(config.Setting.BrokerTopic, h.service.Client())
	
	
	h.usePM = true

	return h
}

func (h *HEPInput) Run() {
	for n := 0; n < runtime.NumCPU(); n++ {
		h.wg.Add(1)
		go h.hepWorker()
	}

	logp.Info("start %s with %#v\n", config.Version, config.Setting)
	go h.logStats()

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
			atomic.AddUint64(&h.stats.HEPCount, 1)
			
			if err != nil {
				log.Logf("error decoding: %v", err)
				continue
			} else if hepPkt.ProtoType == 0 {
				continue
			}

			if h.usePM && hepPkt.ProtoType == 1 {
				statsCount(hepPkt.SIP.FirstMethod)
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
			
				//log.Logf("publishing %s and %s at time: %s\n", ev.CID, ev.FirstMethod, time.Now().UnixNano())
				err := h.pub1.Publish(context.Background(), ev)
				
				if err != nil {
					log.Logf("error publishing: %v", err)
				}
			}
		}
	}
}

func (h *HEPInput) statsCount(FirstMethod string) {
	switch FirstMethod {
		case "INVITE": atomic.AddUint64(&h.stats.INVITECount, 1)
		case "REGISTER": atomic.AddUint64(&h.stats.REGISTERCount, 1)
		case "BYE": atomic.AddUint64(&h.stats.BYECount, 1)
		case "PRACK": atomic.AddUint64(&h.stats.PRACKCount, 1)
		case "180": atomic.AddUint64(&h.stats.180Count, 1)
		case "183": atomic.AddUint64(&h.stats.183Count, 1)
		case "200": atomic.AddUint64(&h.stats.200Count, 1)
		case "400": atomic.AddUint64(&h.stats.400Count, 1)
		case "404": atomic.AddUint64(&h.stats.404Count, 1)
		case "406": atomic.AddUint64(&h.stats.406Count, 1)
		case "408": atomic.AddUint64(&h.stats.408Count, 1)
		case "416": atomic.AddUint64(&h.stats.416Count, 1)
		case "420": atomic.AddUint64(&h.stats.420Count, 1)
		case "422": atomic.AddUint64(&h.stats.422Count, 1)
		case "480": atomic.AddUint64(&h.stats.480Count, 1)
		case "481": atomic.AddUint64(&h.stats.481Count, 1)
		case "484": atomic.AddUint64(&h.stats.484Count, 1)
		case "485": atomic.AddUint64(&h.stats.485Count, 1)
		case "488": atomic.AddUint64(&h.stats.488Count, 1)
		case "500": atomic.AddUint64(&h.stats.500Count, 1)
		case "502": atomic.AddUint64(&h.stats.502Count, 1)
		case "503": atomic.AddUint64(&h.stats.503Count, 1)
		case "504": atomic.AddUint64(&h.stats.504Count, 1)
		case "603": atomic.AddUint64(&h.stats.603Count, 1)
		case "604": atomic.AddUint64(&h.stats.604Count, 1)
		default: atomic.AddUint64(&h.stats.OtherCount, 1)
	}
}


func (h *HEPInput) logStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			logp.Info("stats since last 5 minutes. HEP: %d, INVITECount: %d, REGISTERCount: %d, BYECount: %d, PRACKCount: %d, 180Count: %d, 183Count: %d, 200Count: %d, 400Count: %d, 404Count: %d, 
			406Count: %d, 408Count: %d, 416Count: %d, 420Count: %d, 422Count: %d, 480Count: %d, 481Count: %d, 484Count: %d, 485Count: %d, 488Count: %d, 500Count: %d, 502Count: %d",
			503Count: %d, 504Count: %d, 603Count: %d, 604Count: %d, OtherCount: %d,
				atomic.LoadUint64(&h.stats.HEPCount),
				atomic.LoadUint64(&h.stats.INVITECount),
				atomic.LoadUint64(&h.stats.REGISTERCount),
				atomic.LoadUint64(&h.stats.BYECount),
				atomic.LoadUint64(&h.stats.PRACKCount),
				atomic.LoadUint64(&h.stats.180Count),
				atomic.LoadUint64(&h.stats.183Count),
				atomic.LoadUint64(&h.stats.200Count),
				atomic.LoadUint64(&h.stats.400Count),
				atomic.LoadUint64(&h.stats.404Count),
				atomic.LoadUint64(&h.stats.406Count),
				atomic.LoadUint64(&h.stats.408Count),
				atomic.LoadUint64(&h.stats.416Count),
				atomic.LoadUint64(&h.stats.420Count),
				atomic.LoadUint64(&h.stats.422Count),
				atomic.LoadUint64(&h.stats.480Count),
				atomic.LoadUint64(&h.stats.481Count),
				atomic.LoadUint64(&h.stats.484Count),
				atomic.LoadUint64(&h.stats.485Count),
				atomic.LoadUint64(&h.stats.488Count),
				atomic.LoadUint64(&h.stats.500Count),
				atomic.LoadUint64(&h.stats.502Count),
				atomic.LoadUint64(&h.stats.503Count),
				atomic.LoadUint64(&h.stats.504Count),
				atomic.LoadUint64(&h.stats.603Count),
				atomic.LoadUint64(&h.stats.604Count),
				atomic.LoadUint64(&h.stats.OtherCount)
			)
			atomic.StoreUint64(&h.stats.HEPCount, 0)
			atomic.StoreUint64(&h.stats.INVITECount, 0)
			atomic.StoreUint64(&h.stats.REGISTERCount, 0)
			atomic.StoreUint64(&h.stats.BYECount, 0)
			atomic.StoreUint64(&h.stats.PRACKCount, 0)
			atomic.StoreUint64(&h.stats.180Count, 0)
			atomic.StoreUint64(&h.stats.183Count, 0)
			atomic.StoreUint64(&h.stats.200Count, 0)
			atomic.StoreUint64(&h.stats.400Count, 0)
			atomic.StoreUint64(&h.stats.404Count, 0)
			atomic.StoreUint64(&h.stats.406Count, 0)
			atomic.StoreUint64(&h.stats.408Count, 0)
			atomic.StoreUint64(&h.stats.416Count, 0)
			atomic.StoreUint64(&h.stats.420Count, 0)
			atomic.StoreUint64(&h.stats.422Count, 0)
			atomic.StoreUint64(&h.stats.480Count, 0)
			atomic.StoreUint64(&h.stats.481Count, 0)
			atomic.StoreUint64(&h.stats.484Count, 0)
			atomic.StoreUint64(&h.stats.485Count, 0)
			atomic.StoreUint64(&h.stats.488Count, 0)
			atomic.StoreUint64(&h.stats.500Count, 0)
			atomic.StoreUint64(&h.stats.502Count, 0)
			atomic.StoreUint64(&h.stats.503Count, 0)
			atomic.StoreUint64(&h.stats.504Count, 0)
			atomic.StoreUint64(&h.stats.603Count, 0)
			atomic.StoreUint64(&h.stats.604Count, 0)
			atomic.StoreUint64(&h.stats.OtherCount, 0)

		case <-h.quit:
			h.quit <- true
			return
		}
	}
}


