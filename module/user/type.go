package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	Username        *string    `json:"username,omitempty" db:"username"`
	Email           *string    `json:"email,omitempty" db:"email"`
	Phone           *string    `json:"phone,omitempty" db:"phone"`
	FirstName       *string    `json:"first_name,omitempty" db:"first_name"`
	LastName        *string    `json:"last_name,omitempty" db:"last_name"`
	DisplayName     *string    `json:"display_name,omitempty" db:"display_name"`
	AvatarURL       *string    `json:"avatar_url,omitempty" db:"avatar_url"`
	IsEmailVerified bool       `json:"is_email_verified" db:"is_email_verified"`
	IsPhoneVerified bool       `json:"is_phone_verified" db:"is_phone_verified"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	IsDeleted       bool       `json:"is_deleted" db:"is_deleted"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
}
