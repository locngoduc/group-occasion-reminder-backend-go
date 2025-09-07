package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/locngoduc/gor/module/google"
)

type AuthController struct {
	authService   *AuthService
	googleService *google.GoogleService
	sessionStore  sessions.Store
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
	LogoutAll    bool   `json:"logout_all,omitempty"`
}

func NewAuthController(authService *AuthService, googleService *google.GoogleService, sessionStore sessions.Store) *AuthController {
	return &AuthController{
		authService:   authService,
		googleService: googleService,
		sessionStore:  sessionStore,
	}
}

// generateSecureState generates a cryptographically secure random state token
func (c *AuthController) generateSecureState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return base64.URLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.URLEncoding.EncodeToString(b)
}

// setAuthCookies sets HTTP-only cookies for access and refresh tokens
func (c *AuthController) setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, expiresIn int64) {
	// Access token cookie (shorter expiry)
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(expiresIn),
	}
	http.SetCookie(w, accessCookie)

	// Refresh token cookie (longer expiry)
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/auth/refresh",
		HttpOnly: true,
		Secure:   true, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 3600, // 7 days
	}
	http.SetCookie(w, refreshCookie)
}

// clearAuthCookies clears authentication cookies
func (c *AuthController) clearAuthCookies(w http.ResponseWriter) {
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, accessCookie)

	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/auth/refresh",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, refreshCookie)
}

// writeErrorResponse writes a standardized error response
func (c *AuthController) writeErrorResponse(w http.ResponseWriter, statusCode int, err string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResp := ErrorResponse{
		Error:   err,
		Message: message,
		Code:    statusCode,
	}

	json.NewEncoder(w).Encode(errorResp)
}

// writeJSONResponse writes a JSON response
func (c *AuthController) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// GoogleLogin initiates Google OAuth2 flow
func (c *AuthController) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Create session
	session, err := c.sessionStore.Get(r, "auth-session")
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "session_error", "Failed to create session")
		return
	}

	// Generate and save state token
	state := c.generateSecureState()
	session.Values["oauth_state"] = state
	session.Values["oauth_state_expiry"] = time.Now().Add(10 * time.Minute).Unix()

	// Save session
	if err := session.Save(r, w); err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "session_save_error", "Failed to save session")
		return
	}

	// Redirect to Google
	authURL := c.googleService.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback handles Google OAuth2 callback
func (c *AuthController) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get parameters from URL
	code := r.URL.Query().Get("code")
	receivedState := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check for OAuth errors
	if errorParam != "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "oauth_error", "OAuth authorization failed: "+errorParam)
		return
	}

	if code == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing_code", "Missing authorization code")
		return
	}

	if receivedState == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing_state", "Missing state parameter")
		return
	}

	// Get session
	session, err := c.sessionStore.Get(r, "auth-session")
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "session_error", "Session error")
		return
	}

	// Verify state token
	savedState, ok := session.Values["oauth_state"].(string)
	if !ok || savedState == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "invalid_session_state", "Invalid session state")
		return
	}

	// Check state expiry
	if expiryUnix, exists := session.Values["oauth_state_expiry"].(int64); exists {
		if time.Now().Unix() > expiryUnix {
			c.writeErrorResponse(w, http.StatusBadRequest, "state_expired", "State token expired")
			return
		}
	}

	// Verify state matches
	if savedState != receivedState {
		c.writeErrorResponse(w, http.StatusBadRequest, "state_mismatch", "State mismatch - possible CSRF attack")
		return
	}

	// Cleanup state from session (one-time use)
	delete(session.Values, "oauth_state")
	delete(session.Values, "oauth_state_expiry")
	session.Save(r, w)

	// Get user info from Google
	userInfo, err := c.googleService.HandleCallback(ctx, code)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "google_callback_failed", "Google callback failed: "+err.Error())
		return
	}

	// Convert to our GoogleUserInfo struct
	googleUserInfo := &GoogleUserInfo{
		ID:            userInfo.ID,
		Email:         userInfo.Email,
		VerifiedEmail: userInfo.VerifiedEmail,
		Name:          userInfo.Name,
		GivenName:     userInfo.GivenName,
		FamilyName:    userInfo.FamilyName,
		Picture:       userInfo.Picture,
	}

	// Process login through auth service
	loginResponse, err := c.authService.ProcessGoogleLogin(ctx, googleUserInfo, r)
	if err != nil {
		switch err {
		case ErrUserDeleted:
			c.writeErrorResponse(w, http.StatusForbidden, "user_deleted", "User account has been deleted")
		case ErrUserNotActive:
			c.writeErrorResponse(w, http.StatusForbidden, "user_inactive", "User account is not active")
		default:
			c.writeErrorResponse(w, http.StatusInternalServerError, "login_processing_failed", "Login processing failed: "+err.Error())
		}
		return
	}

	// Set authentication cookies
	c.setAuthCookies(w, loginResponse.AccessToken, loginResponse.RefreshToken, loginResponse.ExpiresIn)

	// Check if request wants JSON response or redirect
	if r.Header.Get("Accept") == "application/json" || r.URL.Query().Get("format") == "json" {
		// Return JSON response
		c.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"user":    loginResponse.User,
			"message": "Login successful",
		})
	} else {
		// Redirect to dashboard or specified redirect URL
		redirectURL := r.URL.Query().Get("redirect_url")
		if redirectURL == "" {
			redirectURL = "/dashboard" // Default redirect
		}
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

// RefreshToken refreshes the access token using refresh token
func (c *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var refreshToken string

	// Try to get refresh token from cookie first
	if cookie, err := r.Cookie("refresh_token"); err == nil {
		refreshToken = cookie.Value
	} else {
		// Try to get from request body
		var req RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			c.writeErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
			return
		}
		refreshToken = req.RefreshToken
	}

	if refreshToken == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing_refresh_token", "Missing refresh token")
		return
	}

	// Refresh the token
	loginResponse, err := c.authService.RefreshAccessToken(ctx, refreshToken)
	if err != nil {
		switch err {
		case ErrInvalidToken:
			c.writeErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid refresh token")
		case ErrSessionExpired:
			c.writeErrorResponse(w, http.StatusUnauthorized, "session_expired", "Session has expired")
		case ErrSessionRevoked:
			c.writeErrorResponse(w, http.StatusUnauthorized, "session_revoked", "Session has been revoked")
		case ErrUserNotFound:
			c.writeErrorResponse(w, http.StatusUnauthorized, "user_not_found", "User not found")
		case ErrUserDeleted:
			c.writeErrorResponse(w, http.StatusForbidden, "user_deleted", "User account has been deleted")
		case ErrUserNotActive:
			c.writeErrorResponse(w, http.StatusForbidden, "user_inactive", "User account is not active")
		default:
			c.writeErrorResponse(w, http.StatusInternalServerError, "refresh_failed", "Token refresh failed: "+err.Error())
		}
		return
	}

	// Update cookies with new tokens
	c.setAuthCookies(w, loginResponse.AccessToken, loginResponse.RefreshToken, loginResponse.ExpiresIn)

	// Return response
	c.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"access_token": loginResponse.AccessToken,
		"expires_in":   loginResponse.ExpiresIn,
		"message":      "Token refreshed successfully",
	})
}

// Logout logs out the user
func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req LogoutRequest
	var refreshToken string

	// Try to get refresh token from cookie first
	if cookie, err := r.Cookie("refresh_token"); err == nil {
		refreshToken = cookie.Value
	} else {
		// Try to get from request body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			c.writeErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
			return
		}
		refreshToken = req.RefreshToken
	}

	// Get user ID from access token for logout all functionality
	var userID *uuid.UUID
	if req.LogoutAll {
		if accessCookie, err := r.Cookie("access_token"); err == nil {
			if uid, err := c.authService.ValidateAccessToken(accessCookie.Value); err == nil {
				userID = uid
			}
		}
		// Also try from Authorization header
		if userID == nil {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if uid, err := c.authService.ValidateAccessToken(token); err == nil {
					userID = uid
				}
			}
		}
	}

	// Perform logout
	if req.LogoutAll && userID != nil {
		// Logout from all devices
		if err := c.authService.LogoutAllDevices(ctx, *userID); err != nil {
			c.writeErrorResponse(w, http.StatusInternalServerError, "logout_failed", "Failed to logout from all devices")
			return
		}
	} else if refreshToken != "" {
		// Logout from current session only
		if err := c.authService.Logout(ctx, refreshToken); err != nil {
			// Don't return error for logout - just log it
			// The cookies will still be cleared
		}
	}

	// Clear authentication cookies
	c.clearAuthCookies(w)

	// Return success response
	c.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

// Profile returns the current user's profile
func (c *AuthController) Profile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from access token
	var accessToken string

	// Try cookie first
	if cookie, err := r.Cookie("access_token"); err == nil {
		accessToken = cookie.Value
	} else {
		// Try Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			accessToken = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if accessToken == "" {
		c.writeErrorResponse(w, http.StatusUnauthorized, "missing_token", "Missing access token")
		return
	}

	// Validate token and get user ID
	userID, err := c.authService.ValidateAccessToken(accessToken)
	if err != nil {
		c.writeErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid access token")
		return
	}

	// Get user from database
	user, err := c.authService.authRepository.FindUserByID(ctx, *userID)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError, "database_error", "Failed to fetch user")
		return
	}

	if user == nil {
		c.writeErrorResponse(w, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	if user.IsDeleted {
		c.writeErrorResponse(w, http.StatusForbidden, "user_deleted", "User account has been deleted")
		return
	}

	if !user.IsActive {
		c.writeErrorResponse(w, http.StatusForbidden, "user_inactive", "User account is not active")
		return
	}

	// Return user profile
	c.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

// AuthMiddleware is a middleware to protect routes that require authentication
func (c *AuthController) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var accessToken string

		// Try cookie first
		if cookie, err := r.Cookie("access_token"); err == nil {
			accessToken = cookie.Value
		} else {
			// Try Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				accessToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if accessToken == "" {
			c.writeErrorResponse(w, http.StatusUnauthorized, "missing_token", "Missing access token")
			return
		}

		// Validate token
		_, err := c.authService.ValidateAccessToken(accessToken)
		if err != nil {
			c.writeErrorResponse(w, http.StatusUnauthorized, "invalid_token", "Invalid access token")
			return
		}

		// Add user ID to request context for use in handlers
		ctx := r.Context()
		// You can add userID to context using context.WithValue if needed
		// ctx = context.WithValue(ctx, "user_id", userID.String())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RegisterRoutes registers all auth routes
func (c *AuthController) RegisterRoutes(router *chi.Mux) {
	// Public routes (chi v5)
	router.Get("/auth/google/login", c.GoogleLogin)
	router.Get("/auth/google/callback", c.GoogleCallback)
	router.Post("/auth/refresh", c.RefreshToken)
	router.Post("/auth/logout", c.Logout)

	// Protected routes
	router.Route("/auth", func(r chi.Router) {
		r.Use(c.AuthMiddleware)
		r.Get("/profile", c.Profile)
	})

	// Health check
	router.Get("/auth/health", func(w http.ResponseWriter, r *http.Request) {
		c.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status": "healthy",
			"time":   time.Now().UTC(),
		})
	})
}
