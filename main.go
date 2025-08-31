package main

import (
	"log"

	"github.com/locngoduc/gor/config"
)

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: %v", err)
	}
	log.Println("Config: %v", config.POSTGRES_USER)
}
