package user

import (
	"time"
)

// =============== USERS ==================
type User struct {
	ID              string     `json:"id"`
	Username        *string    `json:"username,omitempty"`
	Email           *string    `json:"email,omitempty"`
	Phone           *string    `json:"phone,omitempty"`
	FirstName       *string    `json:"first_name,omitempty"`
	LastName        *string    `json:"last_name,omitempty"`
	DisplayName     *string    `json:"display_name,omitempty"`
	AvatarURL       *string    `json:"avatar_url,omitempty"`
	IsEmailVerified bool       `json:"is_email_verified"`
	IsPhoneVerified bool       `json:"is_phone_verified"`
	IsActive        bool       `json:"is_active"`
	IsDeleted       bool       `json:"is_deleted"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
}

// =============== USER AUTHENTICATIONS ==================
type UserAuthentication struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	AuthProvider   string     `json:"auth_provider"`    // maps to ENUM auth_provider_type
	ProviderUserID *string    `json:"provider_user_id"` // nullable (for google/phone)
	PasswordHash   *string    `json:"password_hash"`    // nullable (for password auth only)
	OTPSecret      *string    `json:"otp_secret"`       // nullable (for phone_otp only)
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	IsDeleted      bool       `json:"is_deleted"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

// =============== USER SESSIONS ==================
type UserSession struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	RefreshTokenHash string     `json:"refresh_token_hash"` // store hashed token
	AccessTokenJTI   *string    `json:"access_token_jti"`   // nullable
	DeviceInfo       *string    `json:"device_info"`        // store JSONB as string, pgx can scan into []byte or string
	IPAddress        *string    `json:"ip_address"`
	UserAgent        *string    `json:"user_agent"`
	ExpiresAt        time.Time  `json:"expires_at"`
	CreatedAt        time.Time  `json:"created_at"`
	LastUsedAt       time.Time  `json:"last_used_at"`
	IsRevoked        bool       `json:"is_revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokeReason     *string    `json:"revoke_reason,omitempty"`
}

// =============== USER PREFERENCES ==================
type UserPreference struct {
	UserID          string     `json:"user_id"`
	EnableInApp     bool       `json:"enable_in_app"`
	EnablePush      bool       `json:"enable_push"`
	EnableEmail     bool       `json:"enable_email"`
	EnableSMS       bool       `json:"enable_sms"`
	QuietHoursStart *time.Time `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd   *time.Time `json:"quiet_hours_end,omitempty"`
	Timezone        string     `json:"timezone"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
