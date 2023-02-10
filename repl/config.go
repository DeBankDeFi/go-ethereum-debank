package repl

var Cfg *Config

type Config struct {
	IsWriter      bool
	S3ProxyAddr   string
	KafkaAddr     string
	ChainId       string
	Env           string
	Role          string
	RemoteAddr    string
	ReorgDeep     int
	MetricAddress string
}
