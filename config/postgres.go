package config

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool
var ctx = context.Background()

func InitPostgres(cfg Config) (*pgxpool.Pool, error) {
	stringUrl := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable&timezone=UTC",
		cfg.POSTGRES_USER,
		cfg.POSTGRES_PASSWORD,
		cfg.POSTGRES_HOST,
		cfg.POSTGRES_PORT,
		cfg.POSTGRES_DB,
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
