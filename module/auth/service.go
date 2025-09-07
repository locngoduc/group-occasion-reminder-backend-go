package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/locngoduc/gor/config"
	"github.com/locngoduc/gor/module/user"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrInvalidToken   = errors.New("invalid token")
	ErrSessionExpired = errors.New("session expired")
	ErrSessionRevoked = errors.New("session revoked")
	ErrUserNotActive  = errors.New("user not active")
	ErrUserDeleted    = errors.New("user deleted")
)

type AuthService struct {
	pg_pool        *pgxpool.Pool
	redis_client   *redis.Client
	oauthConfig    *oauth2.Config
	authRepository *AuthRepository
	cfg            *config.Config
}

func NewAuthService(pg_pool *pgxpool.Pool, redis_client *redis.Client, oauthConfig *oauth2.Config, cfg *config.Config) *AuthService {
	return &AuthService{pg_pool: pg_pool, redis_client: redis_client, oauthConfig: oauthConfig, authRepository: NewAuthRepository(pg_pool, redis_client), cfg: cfg}
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type LoginResponse struct {
	User         *user.User `json:"user"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	ExpiresIn    int64      `json:"expires_in"`
}

func (s *AuthService) ProcessGoogleLogin(ctx context.Context, userInfo *GoogleUserInfo, r *http.Request) (*LoginResponse, error) {
	// Try to find existing user by Google ID
	existingUser, err := s.authRepository.FindUserByGoogleID(ctx, userInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user by google id: %w", err)
	}

	var user *user.User

	if existingUser != nil {
		// User exists, check if active
		if existingUser.IsDeleted {
			return nil, ErrUserDeleted
		}
		if !existingUser.IsActive {
			return nil, ErrUserNotActive
		}
		user = existingUser
	} else {
		// Check if user exists with same email
		if userInfo.Email != "" {
			emailUser, err := s.authRepository.FindUserByEmail(ctx, userInfo.Email)
			if err != nil {
				return nil, fmt.Errorf("failed to find user by email: %w", err)
			}

			if emailUser != nil {
				// Link Google auth to existing user
				_, err = s.authRepository.CreateUserAuthentication(
					ctx,
					emailUser.ID,
					AuthProviderGoogle,
					&userInfo.ID,
					nil,
					nil,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to link google auth: %w", err)
				}
				user = emailUser
			} else {
				// Create new user
				user, err = s.createUserFromGoogle(ctx, userInfo)
				if err != nil {
					return nil, fmt.Errorf("failed to create user from google: %w", err)
				}
			}
		} else {
			// Create new user without email
			user, err = s.createUserFromGoogle(ctx, userInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to create user from google: %w", err)
			}
		}
	}

	// Update last login
	if err := s.authRepository.UpdateUserLastLogin(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, expiresIn, err := s.generateTokens(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create session
	deviceInfo, ipAddress, userAgent := s.extractRequestInfo(r)
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	_, err = s.authRepository.CreateSession(
		ctx,
		user.ID,
		refreshToken,
		nil, // access token JTI if using JWTs with JTI
		deviceInfo,
		ipAddress,
		userAgent,
		expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}, nil
}

func (s *AuthService) createUserFromGoogle(ctx context.Context, userInfo *GoogleUserInfo) (*user.User, error) {
	req := &CreateUserRequest{
		Email:       &userInfo.Email,
		FirstName:   &userInfo.GivenName,
		LastName:    &userInfo.FamilyName,
		DisplayName: &userInfo.Name,
		AvatarURL:   &userInfo.Picture,
	}

	user, err := s.authRepository.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}

	// Set email as verified if from Google
	user.IsEmailVerified = userInfo.VerifiedEmail

	// Create Google authentication record
	_, err = s.authRepository.CreateUserAuthentication(
		ctx,
		user.ID,
		AuthProviderGoogle,
		&userInfo.ID,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) generateTokens(userID uuid.UUID) (accessToken, refreshToken string, expiresIn int64, err error) {
	// Generate access token (JWT)
	expiresIn = 3600 // 1 hour
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err = token.SignedString([]byte(s.cfg.JWT_SECRET))
	if err != nil {
		return "", "", 0, err
	}

	// Generate refresh token (random)
	refreshToken, err = s.generateSecureToken(32)
	if err != nil {
		return "", "", 0, err
	}

	return accessToken, refreshToken, expiresIn, nil
}

func (s *AuthService) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *AuthService) extractRequestInfo(r *http.Request) (*string, *string, *string) {
	userAgent := r.Header.Get("User-Agent")
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	}

	var deviceInfo *string
	var ua *string
	var ip *string

	if userAgent != "" {
		ua = &userAgent
	}
	if ipAddress != "" {
		ip = &ipAddress
	}

	return deviceInfo, ip, ua
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWT_SECRET), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &userID, nil
}

func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	// Find session by refresh token
	session, err := s.authRepository.FindSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if session == nil {
		return nil, ErrInvalidToken
	}

	if session.IsRevoked {
		return nil, ErrSessionRevoked
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Get user
	user, err := s.authRepository.FindUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	if user.IsDeleted {
		return nil, ErrUserDeleted
	}

	if !user.IsActive {
		return nil, ErrUserNotActive
	}

	// Generate new tokens
	accessToken, newRefreshToken, expiresIn, err := s.generateTokens(user.ID)
	if err != nil {
		return nil, err
	}

	// Update session last used
	if err := s.authRepository.UpdateSessionLastUsed(ctx, session.ID); err != nil {
		return nil, err
	}

	return &LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.authRepository.FindSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	if session == nil {
		return nil // Already invalid
	}

	return s.authRepository.RevokeSession(ctx, session.ID, "user_logout")
}

func (s *AuthService) LogoutAllDevices(ctx context.Context, userID uuid.UUID) error {
	return s.authRepository.RevokeAllUserSessions(ctx, userID, "logout_all_devices")
}
