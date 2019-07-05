package config

const Version = "heplify-server 1.11"

var Setting HeplifyServer

type HeplifyServer struct {
	HEPAddr            string   `default:"0.0.0.0:9060"`
	HEPTCPAddr         string   `default:""`
	HEPTLSAddr         string   `default:"0.0.0.0:9060"`
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
