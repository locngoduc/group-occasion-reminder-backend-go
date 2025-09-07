package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/locngoduc/gor/config"
	"github.com/locngoduc/gor/module/auth"
	"github.com/locngoduc/gor/module/google"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	pg_pool, err := config.InitPostgres(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Postgres: %v", err)
	}
	redis_client, err := config.InitRedis(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}
	oauthConfig := config.InitOAuth2(&cfg)
	googleService := google.NewGoogleService(oauthConfig)
	sessionStore := sessions.NewCookieStore([]byte(cfg.SESSION_SECRET))
	authService := auth.NewAuthService(pg_pool, redis_client, oauthConfig, &cfg)
	authController := auth.NewAuthController(authService, googleService, sessionStore)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Register routes
	authController.RegisterRoutes(r)

	defer redis_client.Close()
	defer pg_pool.Close()

	log.Printf("Server listening on :%s", cfg.SERVER_PORT)
	if err := http.ListenAndServe(":"+cfg.SERVER_PORT, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
