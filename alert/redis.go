package alert

import (
	"github.com/garyburd/redigo/redis"
	"log"
	"time"
)

var RedisConnPool *redis.Pool

func InitRedisConnPool(url string) {

	dsn := url
	maxIdle := 5
	idleTimeout := 240 * time.Second

	connTimeout := time.Second * 2
	readTimeout := time.Second * 2
	writeTimeout := time.Second * 2

	RedisConnPool = &redis.Pool{
		MaxIdle:     maxIdle,
		IdleTimeout: idleTimeout,
		Dial: func() (redis.Conn, error) {
			c, err := redis.DialTimeout("tcp", dsn, connTimeout, readTimeout, writeTimeout)
			if err != nil {
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: PingRedis,
	}
}

func PingRedis(c redis.Conn, t time.Time) error {
	_, err := c.Do("ping")
	if err != nil {
		log.Println("[ERROR] ping redis fail", err)
	}
	return err
}
