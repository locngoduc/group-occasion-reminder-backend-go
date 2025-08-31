package config

import (
	"context"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client
var RedisCtx = context.Background()

func InitRedis(cfg Config) (*redis.Client, error) {
	addr := fmt.Sprintf("%s:%s", cfg.REDIS_HOST, cfg.REDIS_PORT)

	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: cfg.REDIS_PASSWORD,
		DB:       0,
	})

	_, err := rdb.Ping(RedisCtx).Result()
	if err != nil {
		return nil, err
	}

	log.Println("Connected to Redis")
	return rdb, nil
}
