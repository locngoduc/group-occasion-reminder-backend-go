package config

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func InitOAuth2(cfg *Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.GOOGLE_CLIENT_ID,
		ClientSecret: cfg.GOOGLE_CLIENT_SECRET,
		RedirectURL:  cfg.GOOGLE_REDIRECT_URL,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}
}
