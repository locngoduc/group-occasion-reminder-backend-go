package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type AuthService struct {
	pg_pool        *pgxpool.Pool
	redis_client   *redis.Client
	oauthConfig    *oauth2.Config
	authRepository *AuthRepository
}

func NewAuthService(pg_pool *pgxpool.Pool, redis_client *redis.Client, oauthConfig *oauth2.Config) *AuthService {
	return &AuthService{pg_pool: pg_pool, redis_client: redis_client, oauthConfig: oauthConfig, authRepository: NewAuthRepository(pg_pool, redis_client)}
}
