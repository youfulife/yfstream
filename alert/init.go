package alert

import (
	"database/sql"
	"github.com/chenyoufu/yfstream/g"
	"github.com/wxjuyun/common/model"
	"log"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type AlertConfig struct {
	Enabled   bool
	RuleDB    string
	RedisHost string
}

func InitAlert() {
	InitHistoryBigMap()
	InitRedisConnPool(g.Config().Alert.RedisHost)
	go syncStrategies(g.Config().Alert.MysqlHost)
}

func syncStrategies(url string) {
	duration := 60 * time.Second
	db, err := sql.Open("mysql", url)
	if err != nil {
		log.Fatalln("open db fail:", err)
	}
	defer db.Close()
	db.SetMaxIdleConns(10)
	err = db.Ping()
	if err != nil {
		log.Fatalln("ping db fail:", err)
	}

	for {
		strategies := model.QueryStrategies(db)
		rules := model.QueryRules(db)
		l := new(sync.RWMutex)
		l.Lock()
		globalStrategies = strategies
		globalRules = rules
		l.Unlock()
		log.Println("Sync rules and strategies done...")
		time.Sleep(duration)
	}
}
