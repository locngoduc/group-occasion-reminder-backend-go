-- =============================================
-- GROUP OCCASION REMINDER DATABASE SCHEMA (Enterprise — Final)
-- PostgreSQL 14+
-- Features: UTC-first, Multi-tenant, Soft-delete, Job-locking, Audit, Marketplace (Themes), Payments, Subscriptions
-- =============================================

-- Force current session to UTC for tools that run this file interactively
SET TIME ZONE 'UTC';

-- =============================================
-- DROP TYPES (idempotent rebuild)
-- =============================================
DROP TYPE IF EXISTS auth_provider_type CASCADE;
DROP TYPE IF EXISTS occasion_role_type CASCADE;
DROP TYPE IF EXISTS occasion_recurrence_type CASCADE;
DROP TYPE IF EXISTS reminder_channel_type CASCADE;
DROP TYPE IF EXISTS reminder_offset_type CASCADE;
DROP TYPE IF EXISTS notification_status_type CASCADE;
DROP TYPE IF EXISTS member_status_type CASCADE;

-- =============================================
-- ENUM TYPES
-- =============================================
CREATE TYPE auth_provider_type AS ENUM ('password','google','phone_otp');
CREATE TYPE occasion_role_type AS ENUM ('creator','member');
CREATE TYPE occasion_recurrence_type AS ENUM ('none','daily','weekly','monthly','yearly');
CREATE TYPE reminder_channel_type AS ENUM ('in_app','push','email','sms');
CREATE TYPE reminder_offset_type AS ENUM (
  '5m','15m','30m','1h','3h','6h','12h','1d','3d','7d','14d','30d'
);
CREATE TYPE notification_status_type AS ENUM ('pending','locked','sent','failed','cancelled');
CREATE TYPE member_status_type AS ENUM ('pending','active','inactive','blocked');


-- =============================================
-- USERS & AUTHENTICATION
-- =============================================
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username CITEXT UNIQUE,
  email CITEXT UNIQUE,
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
  CONSTRAINT chk_user_has_identifier CHECK (username IS NOT NULL OR email IS NOT NULL OR phone IS NOT NULL)
);

CREATE TABLE user_authentications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_provider auth_provider_type NOT NULL,
  provider_user_id TEXT,          -- external subject (e.g., Google sub)
  password_hash TEXT,             -- for password auth
  otp_secret TEXT,                -- for phone_otp
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at TIMESTAMPTZ,
  UNIQUE(user_id, auth_provider),
  UNIQUE(auth_provider, provider_user_id),
  CONSTRAINT chk_password_fields CHECK ((auth_provider <> 'password') OR (password_hash IS NOT NULL)),
  CONSTRAINT chk_oauth_fields CHECK ((auth_provider <> 'google') OR (provider_user_id IS NOT NULL)),
  CONSTRAINT chk_phone_fields CHECK ((auth_provider <> 'phone_otp') OR (otp_secret IS NOT NULL))
);

CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token TEXT UNIQUE NOT NULL,
  access_token_jti TEXT UNIQUE,
  device_info JSONB,
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT
);

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
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================
-- OCCASIONS
-- =============================================
CREATE TABLE occasions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  location VARCHAR(500),
  location_coordinates POINT,
  date_time TIMESTAMPTZ NOT NULL,
  end_date_time TIMESTAMPTZ,
  recurrence_type occasion_recurrence_type NOT NULL DEFAULT 'none',
  recurrence_end_date DATE,
  recurrence_interval INTEGER NOT NULL DEFAULT 1,
  recurrence_days_of_week INTEGER[],
  recurrence_day_of_month INTEGER,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  banner_image_url VARCHAR(500),
  color_theme VARCHAR(7),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  CONSTRAINT chk_recurrence_interval CHECK (recurrence_interval > 0)
);

CREATE TABLE occasion_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role occasion_role_type NOT NULL DEFAULT 'member',
  status member_status_type NOT NULL DEFAULT 'active',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  invited_by UUID REFERENCES users(id),
  last_viewed_at TIMESTAMPTZ,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at TIMESTAMPTZ,
  UNIQUE(occasion_id, user_id)
);

CREATE TABLE occasion_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
  invite_code VARCHAR(20) UNIQUE NOT NULL,
  qr_code_url VARCHAR(500),
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  max_uses INTEGER,
  current_uses INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  CONSTRAINT chk_invite_expires_future CHECK (expires_at IS NULL OR expires_at > NOW())
);

-- =============================================
-- REMINDERS & NOTIFICATIONS (with partitioning & locking)
-- =============================================
CREATE TABLE occasion_reminders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
  channel reminder_channel_type NOT NULL,
  remind_before reminder_offset_type NOT NULL,
  message_template TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  UNIQUE(occasion_id, channel, remind_before)
);

CREATE TABLE user_reminder_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
  reminder_id UUID NOT NULL REFERENCES occasion_reminders(id) ON DELETE CASCADE,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, reminder_id)
);

-- Job queue with distributed locking fields and partitioning by scheduled_for
CREATE TABLE notification_queue (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id),
  occasion_id UUID NOT NULL REFERENCES occasions(id) ON DELETE CASCADE,
  reminder_id UUID NOT NULL REFERENCES occasion_reminders(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel reminder_channel_type NOT NULL,
  scheduled_for TIMESTAMPTZ NOT NULL,
  status notification_status_type NOT NULL DEFAULT 'pending',
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 3,
  priority INTEGER NOT NULL DEFAULT 100,
  next_attempt_at TIMESTAMPTZ,
  locked_at TIMESTAMPTZ,
  locked_by TEXT,
  last_error TEXT,
  message_payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ,
  UNIQUE(occasion_id, reminder_id, user_id, scheduled_for)
) PARTITION BY RANGE (scheduled_for);

-- Example monthly partition (create partitions via migrations)
CREATE TABLE IF NOT EXISTS notification_queue_2025_09 PARTITION OF notification_queue
  FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

CREATE TABLE notification_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id),
  queue_id UUID REFERENCES notification_queue(id),
  user_id UUID NOT NULL REFERENCES users(id),
  occasion_id UUID NOT NULL REFERENCES occasions(id),
  channel reminder_channel_type NOT NULL,
  status notification_status_type NOT NULL,
  error_message TEXT,
  metadata JSONB,
  sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (sent_at);

CREATE TABLE IF NOT EXISTS notification_log_2025_09 PARTITION OF notification_log
  FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

-- =============================================
-- AUDIT TRAIL & ACTIVITY
-- =============================================
CREATE TABLE user_activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  organization_id UUID REFERENCES organizations(id),
  action TEXT NOT NULL,
  ip_address INET,
  user_agent TEXT,
  details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================
-- THEME MARKETPLACE (Design, Versions, Purchases, Ratings, Approvals, Payouts)
-- =============================================

CREATE TABLE theme_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE creator_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  display_name VARCHAR(150),
  bio TEXT,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_meta JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE occasion_themes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category_id UUID REFERENCES theme_categories(id) ON DELETE SET NULL,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  short_description TEXT,
  full_description TEXT,
  cover_image_url VARCHAR(500),
  preview_images TEXT[],
  color_palette VARCHAR(7)[],
  tags TEXT[],
  default_price_cents INTEGER NOT NULL DEFAULT 0,
  currency VARCHAR(10) NOT NULL DEFAULT 'USD',
  is_published BOOLEAN NOT NULL DEFAULT FALSE,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

-- Theme versions to allow updates & backwards compatibility
CREATE TABLE theme_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  theme_id UUID NOT NULL REFERENCES occasion_themes(id) ON DELETE CASCADE,
  version INTEGER NOT NULL DEFAULT 1,
  assets JSONB,         -- URLs, layout json, templates, thumbnails
  manifest JSONB,       -- schema of variables the theme expects
  changelog TEXT,
  is_published BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(theme_id, version)
);

-- Marketplace approvals & status
CREATE TABLE theme_moderation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  theme_id UUID NOT NULL REFERENCES occasion_themes(id) ON DELETE CASCADE,
  moderator_id UUID REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected
  notes TEXT,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Purchases
CREATE TABLE theme_purchases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  theme_id UUID NOT NULL REFERENCES occasion_themes(id) ON DELETE CASCADE,
  buyer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version_id UUID REFERENCES theme_versions(id),
  price_cents INTEGER NOT NULL,
  currency VARCHAR(10) NOT NULL,
  purchased_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  platform_fee_cents INTEGER NOT NULL DEFAULT 0,
  creator_earnings_cents INTEGER NOT NULL DEFAULT 0,
  payment_reference TEXT
);

-- Applied themes to occasions
CREATE TABLE occasion_theme_applied (
  occasion_id UUID PRIMARY KEY REFERENCES occasions(id) ON DELETE CASCADE,
  theme_id UUID NOT NULL REFERENCES occasion_themes(id) ON DELETE RESTRICT,
  version_id UUID REFERENCES theme_versions(id),
  applied_by UUID NOT NULL REFERENCES users(id),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reviews & ratings
CREATE TABLE theme_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  theme_id UUID NOT NULL REFERENCES occasion_themes(id) ON DELETE CASCADE,
  buyer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rating SMALLINT NOT NULL CHECK (rating >= 1 AND rating <= 5),
  title TEXT,
  body TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(theme_id, buyer_id) -- one review per buyer per theme
);

-- Payout requests & ledger for creators
CREATE TABLE payouts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount_cents INTEGER NOT NULL,
  currency VARCHAR(10) NOT NULL DEFAULT 'USD',
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'requested', -- requested, paid, cancelled, failed
  payment_method JSONB, -- e.g. stripe account id, paypal email
  payment_reference TEXT,
  platform_fee_cents INTEGER NOT NULL DEFAULT 0
);

-- Marketplace subscriptions (optional)
CREATE TABLE marketplace_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) NOT NULL,
  description TEXT,
  monthly_price_cents INTEGER NOT NULL DEFAULT 0,
  benefits JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_id UUID NOT NULL REFERENCES marketplace_plans(id) ON DELETE RESTRICT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ends_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'active'
);

-- Webhook logs for payment providers
CREATE TABLE payment_webhook_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  payload JSONB,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed BOOLEAN NOT NULL DEFAULT FALSE,
  processed_at TIMESTAMPTZ
);

-- =============================================
-- INDEXES & PERFORMANCE
-- =============================================
CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL AND is_deleted = FALSE;
CREATE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL AND is_deleted = FALSE;
CREATE INDEX idx_users_phone ON users(phone) WHERE phone IS NOT NULL AND is_deleted = FALSE;
CREATE INDEX idx_user_auth_provider ON user_authentications(user_id, auth_provider) WHERE is_deleted = FALSE;
CREATE INDEX idx_user_sessions_valid ON user_sessions(expires_at) WHERE is_revoked = FALSE;
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id) WHERE is_revoked = FALSE;

CREATE INDEX idx_occasions_creator ON occasions(created_by) WHERE is_deleted = FALSE AND is_active = TRUE;
CREATE INDEX idx_occasions_datetime ON occasions(date_time) WHERE is_deleted = FALSE AND is_active = TRUE;
CREATE INDEX idx_occasions_recurrence ON occasions(recurrence_type) WHERE is_deleted = FALSE AND recurrence_type <> 'none';

CREATE INDEX idx_occasion_members_user ON occasion_members(user_id, status) WHERE is_deleted = FALSE AND status = 'active';
CREATE INDEX idx_occasion_members_occ ON occasion_members(occasion_id, status) WHERE is_deleted = FALSE AND status = 'active';

CREATE INDEX idx_invitations_code ON occasion_invitations(invite_code) WHERE is_active = TRUE AND is_deleted = FALSE;
CREATE INDEX idx_reminders_occasion ON occasion_reminders(occasion_id) WHERE is_deleted = FALSE AND is_active = TRUE;
CREATE INDEX idx_user_reminder_prefs ON user_reminder_preferences(user_id, occasion_id);

CREATE INDEX idx_nq_fetch ON notification_queue (scheduled_for, priority) WHERE status = 'pending' AND locked_at IS NULL;
CREATE INDEX idx_nq_locked ON notification_queue (locked_by, locked_at) WHERE status = 'locked';
CREATE INDEX idx_nq_next_attempt ON notification_queue (next_attempt_at) WHERE status IN ('pending','failed');

CREATE INDEX idx_nlog_user_date ON notification_log(user_id, sent_at);

CREATE INDEX idx_themes_creator ON occasion_themes(created_by) WHERE is_deleted = FALSE;
CREATE INDEX idx_themes_category ON occasion_themes(category_id) WHERE is_published = TRUE AND is_deleted = FALSE;
CREATE INDEX idx_theme_purchases_buyer ON theme_purchases(buyer_id);
CREATE INDEX idx_theme_purchases_theme ON theme_purchases(theme_id);
CREATE INDEX idx_theme_reviews_theme ON theme_reviews(theme_id);

-- =============================================
-- TRIGGERS (updated_at touch, soft-delete helpers)
-- =============================================
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

-- Attach to tables that have updated_at
CREATE TRIGGER trg_org_updated BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_uauth_updated BEFORE UPDATE ON user_authentications FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_occasions_updated BEFORE UPDATE ON occasions FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_occrem_updated BEFORE UPDATE ON occasion_reminders FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_userprefs_updated BEFORE UPDATE ON user_preferences FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_orgmembers_updated BEFORE UPDATE ON organization_members FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_themes_updated BEFORE UPDATE ON occasion_themes FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_creator_profiles_updated BEFORE UPDATE ON creator_profiles FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- Soft-delete helper: mark deleted_at when is_deleted set true
CREATE OR REPLACE FUNCTION mark_deleted_at()
RETURNS TRIGGER AS $$
BEGIN
  IF (TG_OP = 'UPDATE') THEN
    IF (NEW.is_deleted = TRUE AND OLD.is_deleted = FALSE) THEN
      NEW.deleted_at = NOW();
    END IF;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

-- Apply to tables that have is_deleted
CREATE TRIGGER trg_users_soft_delete BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION mark_deleted_at();
CREATE TRIGGER trg_occasions_soft_delete BEFORE UPDATE ON occasions FOR EACH ROW EXECUTE FUNCTION mark_deleted_at();
CREATE TRIGGER trg_uauth_soft_delete BEFORE UPDATE ON user_authentications FOR EACH ROW EXECUTE FUNCTION mark_deleted_at();
CREATE TRIGGER trg_reminders_soft_delete BEFORE UPDATE ON occasion_reminders FOR EACH ROW EXECUTE FUNCTION mark_deleted_at();
CREATE TRIGGER trg_themes_soft_delete BEFORE UPDATE ON occasion_themes FOR EACH ROW EXECUTE FUNCTION mark_deleted_at();

-- =============================================
-- UTC HELPERS
-- =============================================
CREATE OR REPLACE FUNCTION utc_now()
RETURNS TIMESTAMPTZ AS $$
BEGIN
  RETURN CURRENT_TIMESTAMP AT TIME ZONE 'UTC';
END; $$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION format_utc_iso8601(ts TIMESTAMPTZ)
RETURNS TEXT AS $$
BEGIN
  RETURN to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
END; $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================
-- SAMPLE QUERIES & WORKER PATTERNS
-- =============================================
-- 1) Backfill example: assign default organization to existing users
-- UPDATE users SET