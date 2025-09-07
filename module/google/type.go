package google

type GoogleUser struct {
	Sub           string `json:"sub"` // Google user ID (unique)
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"email_verified"` // true if email is verified
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"` // avatar
	Locale        string `json:"locale"`
}
