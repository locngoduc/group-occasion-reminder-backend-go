package auth

import (
	"database/sql/driver"
	"time"

	"github.com/google/uuid"
)

type AuthProviderType string

const (
	AuthProviderPassword AuthProviderType = "password"
	AuthProviderGoogle   AuthProviderType = "google"
	AuthProviderPhoneOTP AuthProviderType = "phone_otp"
)

func (a AuthProviderType) Value() (driver.Value, error) {
	return string(a), nil
}

type CreateUserRequest struct {
	Username    *string `json:"username,omitempty"`
	Email       *string `json:"email,omitempty"`
	Phone       *string `json:"phone,omitempty"`
	FirstName   *string `json:"first_name,omitempty"`
	LastName    *string `json:"last_name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

type UserAuthentication struct {
	ID             uuid.UUID        `json:"id" db:"id"`
	UserID         uuid.UUID        `json:"user_id" db:"user_id"`
	AuthProvider   AuthProviderType `json:"auth_provider" db:"auth_provider"`
	ProviderUserID *string          `json:"provider_user_id,omitempty" db:"provider_user_id"`
	PasswordHash   *string          `json:"-" db:"password_hash"`
	OTPSecret      *string          `json:"-" db:"otp_secret"`
	CreatedAt      time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at" db:"updated_at"`
	IsDeleted      bool             `json:"is_deleted" db:"is_deleted"`
	DeletedAt      *time.Time       `json:"deleted_at,omitempty" db:"deleted_at"`
}

type UserSession struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	UserID           uuid.UUID  `json:"user_id" db:"user_id"`
	RefreshTokenHash string     `json:"-" db:"refresh_token_hash"`
	AccessTokenJTI   *string    `json:"access_token_jti,omitempty" db:"access_token_jti"`
	DeviceInfo       *string    `json:"device_info,omitempty" db:"device_info"`
	IPAddress        *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent        *string    `json:"user_agent,omitempty" db:"user_agent"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt       time.Time  `json:"last_used_at" db:"last_used_at"`
	IsRevoked        bool       `json:"is_revoked" db:"is_revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokeReason     *string    `json:"revoke_reason,omitempty" db:"revoke_reason"`
}
