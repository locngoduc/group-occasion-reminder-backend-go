package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/locngoduc/gor/module/user"
	"github.com/redis/go-redis/v9"
)

type AuthRepository struct {
	pg_pool      *pgxpool.Pool
	redis_client *redis.Client
}

func NewAuthRepository(pg_pool *pgxpool.Pool, redis_client *redis.Client) *AuthRepository {
	return &AuthRepository{pg_pool: pg_pool, redis_client: redis_client}
}

// user.User operations
func (r *AuthRepository) CreateUser(ctx context.Context, req *CreateUserRequest) (*user.User, error) {
	query := `
		INSERT INTO users (username, email, phone, first_name, last_name, display_name, avatar_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, username, email, phone, first_name, last_name, display_name, avatar_url,
				  is_email_verified, is_phone_verified, is_active, is_deleted,
				  created_at, updated_at, deleted_at, last_login_at`

	var user user.User
	err := r.pg_pool.QueryRow(ctx, query,
		req.Username, req.Email, req.Phone, req.FirstName,
		req.LastName, req.DisplayName, req.AvatarURL,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.Phone,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.AvatarURL,
		&user.IsEmailVerified, &user.IsPhoneVerified, &user.IsActive, &user.IsDeleted,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastLoginAt,
	)

	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) FindUserByEmail(ctx context.Context, email string) (*user.User, error) {
	query := `
		SELECT id, username, email, phone, first_name, last_name, display_name, avatar_url,
			   is_email_verified, is_phone_verified, is_active, is_deleted,
			   created_at, updated_at, deleted_at, last_login_at
		FROM users
		WHERE email = $1 AND is_deleted = false`

	var user user.User
	err := r.pg_pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.Phone,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.AvatarURL,
		&user.IsEmailVerified, &user.IsPhoneVerified, &user.IsActive, &user.IsDeleted,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastLoginAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) FindUserByID(ctx context.Context, userID uuid.UUID) (*user.User, error) {
	query := `
		SELECT id, username, email, phone, first_name, last_name, display_name, avatar_url,
			   is_email_verified, is_phone_verified, is_active, is_deleted,
			   created_at, updated_at, deleted_at, last_login_at
		FROM users
		WHERE id = $1 AND is_deleted = false`

	var user user.User
	err := r.pg_pool.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.Phone,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.AvatarURL,
		&user.IsEmailVerified, &user.IsPhoneVerified, &user.IsActive, &user.IsDeleted,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastLoginAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) UpdateUserLastLogin(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET last_login_at = NOW() WHERE id = $1`
	_, err := r.pg_pool.Exec(ctx, query, userID)
	return err
}

// Authentication operations
func (r *AuthRepository) CreateUserAuthentication(ctx context.Context, userID uuid.UUID, authProvider AuthProviderType, providerUserID *string, passwordHash *string, otpSecret *string) (*UserAuthentication, error) {
	query := `
		INSERT INTO user_authentications (user_id, auth_provider, provider_user_id, password_hash, otp_secret)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, auth_provider, provider_user_id, password_hash, otp_secret,
				  created_at, updated_at, is_deleted, deleted_at`

	var auth UserAuthentication
	err := r.pg_pool.QueryRow(ctx, query,
		userID, authProvider, providerUserID, passwordHash, otpSecret,
	).Scan(
		&auth.ID, &auth.UserID, &auth.AuthProvider, &auth.ProviderUserID,
		&auth.PasswordHash, &auth.OTPSecret, &auth.CreatedAt, &auth.UpdatedAt,
		&auth.IsDeleted, &auth.DeletedAt,
	)

	if err != nil {
		return nil, err
	}
	return &auth, nil
}

func (r *AuthRepository) FindUserAuthByProvider(ctx context.Context, userID uuid.UUID, authProvider AuthProviderType) (*UserAuthentication, error) {
	query := `
		SELECT id, user_id, auth_provider, provider_user_id, password_hash, otp_secret,
			   created_at, updated_at, is_deleted, deleted_at
		FROM user_authentications
		WHERE user_id = $1 AND auth_provider = $2 AND is_deleted = false`

	var auth UserAuthentication
	err := r.pg_pool.QueryRow(ctx, query, userID, authProvider).Scan(
		&auth.ID, &auth.UserID, &auth.AuthProvider, &auth.ProviderUserID,
		&auth.PasswordHash, &auth.OTPSecret, &auth.CreatedAt, &auth.UpdatedAt,
		&auth.IsDeleted, &auth.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &auth, nil
}

func (r *AuthRepository) FindUserByGoogleID(ctx context.Context, googleID string) (*user.User, error) {
	query := `
		SELECT u.id, u.username, u.email, u.phone, u.first_name, u.last_name, u.display_name, u.avatar_url,
			   u.is_email_verified, u.is_phone_verified, u.is_active, u.is_deleted,
			   u.created_at, u.updated_at, u.deleted_at, u.last_login_at
		FROM users u
		JOIN user_authentications ua ON u.id = ua.user_id
		WHERE ua.auth_provider = 'google' AND ua.provider_user_id = $1 
			  AND u.is_deleted = false AND ua.is_deleted = false`

	var user user.User
	err := r.pg_pool.QueryRow(ctx, query, googleID).Scan(
		&user.ID, &user.Username, &user.Email, &user.Phone,
		&user.FirstName, &user.LastName, &user.DisplayName, &user.AvatarURL,
		&user.IsEmailVerified, &user.IsPhoneVerified, &user.IsActive, &user.IsDeleted,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastLoginAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// Session operations
func (r *AuthRepository) CreateSession(ctx context.Context, userID uuid.UUID, refreshToken string, accessTokenJTI *string, deviceInfo, ipAddress, userAgent *string, expiresAt time.Time) (*UserSession, error) {
	// Hash the refresh token before storing
	hash := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash := hex.EncodeToString(hash[:])

	query := `
		INSERT INTO user_sessions (user_id, refresh_token_hash, access_token_jti, device_info, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, refresh_token_hash, access_token_jti, device_info, ip_address, user_agent,
				  expires_at, created_at, last_used_at, is_revoked, revoked_at, revoke_reason`

	var session UserSession
	err := r.pg_pool.QueryRow(ctx, query,
		userID, refreshTokenHash, accessTokenJTI, deviceInfo, ipAddress, userAgent, expiresAt,
	).Scan(
		&session.ID, &session.UserID, &session.RefreshTokenHash, &session.AccessTokenJTI,
		&session.DeviceInfo, &session.IPAddress, &session.UserAgent, &session.ExpiresAt,
		&session.CreatedAt, &session.LastUsedAt, &session.IsRevoked, &session.RevokedAt, &session.RevokeReason,
	)

	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *AuthRepository) FindSessionByRefreshToken(ctx context.Context, refreshToken string) (*UserSession, error) {
	hash := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash := hex.EncodeToString(hash[:])

	query := `
		SELECT id, user_id, refresh_token_hash, access_token_jti, device_info, ip_address, user_agent,
			   expires_at, created_at, last_used_at, is_revoked, revoked_at, revoke_reason
		FROM user_sessions
		WHERE refresh_token_hash = $1 AND is_revoked = false AND expires_at > NOW()`

	var session UserSession
	err := r.pg_pool.QueryRow(ctx, query, refreshTokenHash).Scan(
		&session.ID, &session.UserID, &session.RefreshTokenHash, &session.AccessTokenJTI,
		&session.DeviceInfo, &session.IPAddress, &session.UserAgent, &session.ExpiresAt,
		&session.CreatedAt, &session.LastUsedAt, &session.IsRevoked, &session.RevokedAt, &session.RevokeReason,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &session, nil
}

func (r *AuthRepository) UpdateSessionLastUsed(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE user_sessions SET last_used_at = NOW() WHERE id = $1`
	_, err := r.pg_pool.Exec(ctx, query, sessionID)
	return err
}

func (r *AuthRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	query := `
		UPDATE user_sessions 
		SET is_revoked = true, revoked_at = NOW(), revoke_reason = $2
		WHERE id = $1`
	_, err := r.pg_pool.Exec(ctx, query, sessionID, reason)
	return err
}

func (r *AuthRepository) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	query := `
		UPDATE user_sessions 
		SET is_revoked = true, revoked_at = NOW(), revoke_reason = $2
		WHERE user_id = $1 AND is_revoked = false`
	_, err := r.pg_pool.Exec(ctx, query, userID, reason)
	return err
}
