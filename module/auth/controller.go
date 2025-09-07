package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/locngoduc/gor/module/google"
)

type AuthController struct {
	authService   *AuthService
	googleService *google.GoogleService
	sessionStore  sessions.Store
}

func NewAuthController(authService *AuthService, googleService *google.GoogleService, sessionStore sessions.Store) *AuthController {
	return &AuthController{authService: authService, googleService: googleService, sessionStore: sessionStore}
}

func (c *AuthController) generateSecureState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return base64.URLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.URLEncoding.EncodeToString(b)
}

func (c *AuthController) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Tạo session
	session, err := c.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	// Tạo và lưu state token
	state := c.generateSecureState()
	session.Values["oauth_state"] = state
	session.Values["oauth_state_expiry"] = time.Now().Add(10 * time.Minute).Unix()

	// Lưu session
	if err := session.Save(r, w); err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect đến Google
	authURL := c.googleService.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback is the callback endpoint for Google OAuth2
func (c *AuthController) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Lấy parameters từ URL
	code := r.URL.Query().Get("code")
	receivedState := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	if receivedState == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	// Lấy session
	session, err := c.sessionStore.Get(r, "auth-session")
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	// Verify state token
	savedState, ok := session.Values["oauth_state"].(string)
	if !ok || savedState == "" {
		http.Error(w, "invalid session state", http.StatusBadRequest)
		return
	}

	// Check state expiry
	if expiryUnix, exists := session.Values["oauth_state_expiry"].(int64); exists {
		if time.Now().Unix() > expiryUnix {
			http.Error(w, "state token expired", http.StatusBadRequest)
			return
		}
	}

	// Verify state matches
	if savedState != receivedState {
		http.Error(w, "state mismatch - possible CSRF attack", http.StatusBadRequest)
		return
	}

	// Cleanup state từ session (one-time use)
	delete(session.Values, "oauth_state")
	delete(session.Values, "oauth_state_expiry")
	session.Save(r, w)

	// Gọi Google service để lấy user info
	userInfo, err := c.googleService.HandleCallback(ctx, code)
	if err != nil {
		http.Error(w, "google callback failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: Tại đây bạn có thể:
	// 1. Tạo user trong database nếu chưa tồn tại
	// 2. Tạo JWT token cho user
	// 3. Set authentication cookie
	// 4. Redirect đến trang dashboard thay vì return JSON

	// Example: return user info as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}
