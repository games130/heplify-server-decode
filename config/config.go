package config

const Version = "heplify-server 1.11"

var Setting HeplifyServer

type HeplifyServer struct {
	HEPAddr            string   `default:"0.0.0.0:9060"`
	HEPTCPAddr         string   `default:""`
	HEPTLSAddr         string   `default:"0.0.0.0:9060"`
	CGRAddr            string   `default:""`
	ESAddr             string   `default:""`
	ESDiscovery        bool     `default:"true"`
	ESUser             string   `default:""`
	ESPass             string   `default:""`
	LokiURL            string   `default:""`
	LokiBulk           int      `default:"400"`
	LokiTimer          int      `default:"4"`
	LokiBuffer         int      `default:"100000"`
	LokiHEPFilter      []int    `default:"1,5,100"`
	PromAddr           string   `default:":9096"`
	PromTargetIP       string   `default:""`
	PromTargetName     string   `default:""`
	Dedup              bool     `default:"false"`
	DiscardMethod      []string `default:""`
	FilterHost         []string `default:""`
	AlegIDs            []string `default:""`
	CustomHeader       []string `default:""`
	LogDbg             string   `default:""`
	LogLvl             string   `default:"info"`
	LogStd             bool     `default:"false"`
	LogSys             bool     `default:"false"`
	Config             string   `default:"./heplify-server.toml"`
	ConfigHTTPAddr     string   `default:""`
	ConfigHTTPPW       string   `default:""`
}
