package google

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"
)

type GoogleService struct {
	oauthConfig *oauth2.Config
}

func NewGoogleService(oauthConfig *oauth2.Config) *GoogleService {
	return &GoogleService{oauthConfig: oauthConfig}
}

func (s *GoogleService) GetAuthURL(state string) string {
	return s.oauthConfig.AuthCodeURL(state)
}

func (s *GoogleService) HandleCallback(ctx context.Context, code string) (*GoogleUser, error) {
	token, err := s.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	// Get user info
	client := s.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &userInfo, nil
}
