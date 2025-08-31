package main

import (
	"log"

	"github.com/locngoduc/gor/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: %v", err)
	}
	pg_pool, err := config.InitPostgres(cfg)
	if err != nil {
		log.Fatal("Failed to initialize Postgres: %v", err)
	}
	defer pg_pool.Close()
}
