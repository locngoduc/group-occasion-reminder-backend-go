-- =============================================
-- USER & AUTHENTICATION SCHEMA (PostgreSQL 14+)
-- All timestamps stored in UTC
-- =============================================

SET TIME ZONE 'UTC';

-- ===================== ENUMS =====================
CREATE TYPE auth_provider_type AS ENUM ('password','google','phone_otp');

-- ===================== USERS =====================
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  phone VARCHAR(20) UNIQUE,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  display_name VARCHAR(150),
  avatar_url VARCHAR(500),
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  is_phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  CONSTRAINT chk_user_has_identifier CHECK (
    username IS NOT NULL OR email IS NOT NULL OR phone IS NOT NULL
  )
);

-- ================= USER AUTHENTICATIONS =================
CREATE TABLE user_authentications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_provider auth_provider_type NOT NULL,
  provider_user_id TEXT,      -- external subject (Google sub, phone number, etc.)
  password_hash TEXT,         -- for password auth
  otp_secret TEXT,            -- for phone_otp
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at TIMESTAMPTZ,
  UNIQUE(user_id, auth_provider),
  -- enforce data presence rules
  CONSTRAINT chk_password_fields CHECK (
    auth_provider <> 'password' OR password_hash IS NOT NULL
  ),
  CONSTRAINT chk_google_fields CHECK (
    auth_provider <> 'google' OR provider_user_id IS NOT NULL
  ),
  CONSTRAINT chk_phone_fields CHECK (
    auth_provider <> 'phone_otp' OR otp_secret IS NOT NULL
  )
);

-- Better unique constraint for provider_user_id (avoid NULL conflicts)
CREATE UNIQUE INDEX uniq_google_provider_user
  ON user_authentications(provider_user_id)
  WHERE auth_provider = 'google';

CREATE UNIQUE INDEX uniq_phone_provider_user
  ON user_authentications(provider_user_id)
  WHERE auth_provider = 'phone_otp';

-- ================= USER SESSIONS =================
CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT UNIQUE NOT NULL,   -- store hash, not raw token
  access_token_jti TEXT UNIQUE,              -- JWT ID if used
  device_info JSONB,
  ip_address TEXT,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT
);

-- ================= USER PREFERENCES =================
CREATE TABLE user_preferences (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  enable_in_app BOOLEAN NOT NULL DEFAULT TRUE,
  enable_push BOOLEAN NOT NULL DEFAULT TRUE,
  enable_email BOOLEAN NOT NULL DEFAULT TRUE,
  enable_sms BOOLEAN NOT NULL DEFAULT FALSE,
  quiet_hours_start TIME,
  quiet_hours_end TIME,
  timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_quiet_hours CHECK (
    quiet_hours_start IS NULL OR quiet_hours_end IS NULL 
    OR quiet_hours_start <> quiet_hours_end
  )
);

-- ================= AUTO-UPDATE updated_at =================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to tables with updated_at
CREATE TRIGGER trg_users_updated
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_user_auth_updated
BEFORE UPDATE ON user_authentications
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_sessions_updated
BEFORE UPDATE ON user_sessions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_prefs_updated
BEFORE UPDATE ON user_preferences
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
