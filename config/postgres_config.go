package config

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool
var ctx = context.Background()

func InitPostgres(config Config) (*pgxpool.Pool, error) {
	stringUrl := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable&timezone=UTC",
		config.POSTGRES_USER,
		config.POSTGRES_PASSWORD,
		config.POSTGRES_HOST,
		config.POSTGRES_PORT,
		config.POSTGRES_DB,
	)
	pool, err := pgxpool.New(ctx, stringUrl)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	log.Println("Connected to Postgres")
	return pool, nil
}
