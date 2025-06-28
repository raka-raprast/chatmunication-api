package config

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
	RedisCtx    = context.Background()
)

func InitRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // change if not default
		Password: "",               // no password set
		DB:       0,                // use default DB
	})
}
