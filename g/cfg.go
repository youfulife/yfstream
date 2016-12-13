package g

import (
	"encoding/json"
	"github.com/toolkits/file"
	"log"
	"sync"
)

//HTTPConfig for debug
type HTTPConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
}

//KafkaConfig for pull
type KafkaConfig struct {
	Enabled    bool     `json:"enabled"`
	Topics     []string `json:"topics"`
	Brokers    []string `json:"brokers"`
	ConsumerID string   `json:"consumerId"`
}

//ESConfig for dump
type ESConfig struct {
	Enabled     bool   `json:"enabled"`
	Interval    int64  `json:"interval"`
	BulkURL     string `json:"bulkUrl"`
	IndexPrefix string `json:"indexPrefix"`
	IndexSuffix string `json:"indexSuffix"`
}

//RedisConfig for dump
type RedisConfig struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
}

//PullConfig for data source
type PullConfig struct {
	Kafka KafkaConfig `json:"kafka"`
}

//DumpConfig for data storage
type DumpConfig struct {
	ES    ESConfig    `json:"es"`
	Redis RedisConfig `json:"redis"`
}

//GlobalConfig ...
type GlobalConfig struct {
	Debug bool        `json:"debug"`
	HTTP  *HTTPConfig `json:"http"`
	Pull  *PullConfig `json:"pull"`
	Dump  *DumpConfig `json:"dump"`
}

var (
	config *GlobalConfig
	//VERSION ...
	VERSION    = "0.1"
	configLock = new(sync.RWMutex)
)

//Config returns GlobalConfig struct
func Config() *GlobalConfig {
	configLock.RLock()
	defer configLock.RUnlock()
	return config
}

func (c *GlobalConfig) String() string {
	s, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(s)
}

//ParseConfig init the global config file
func ParseConfig(cfg string) {
	if cfg == "" {
		log.Fatalln("use -c to specify configuration file")
	}

	if !file.IsExist(cfg) {
		log.Fatalln("config file:", cfg, "is not existent")
	}

	configContent, err := file.ToTrimString(cfg)
	if err != nil {
		log.Fatalln("read config file:", cfg, "fail:", err)
	}

	var c GlobalConfig
	err = json.Unmarshal([]byte(configContent), &c)
	if err != nil {
		log.Fatalln("parse config file:", cfg, "fail:", err)
	}

	configLock.Lock()
	defer configLock.Unlock()

	config = &c

	log.Println("read config file:", cfg, "successfully")
}
