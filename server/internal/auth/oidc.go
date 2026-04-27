package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider 封装标准 OIDC Relying Party。
// OIDC 未配置时为 nil；配置有误时 NewOIDCProvider 返回 error。
type OIDCProvider struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	OAuth2Config *oauth2.Config
	Issuer       string
}

func NewOIDCProvider() (*OIDCProvider, error) {
	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil, nil
	}

	redirectURL := os.Getenv("OIDC_REDIRECT_URI")
	if redirectURL == "" {
		appURL := os.Getenv("MULTICA_APP_URL")
		if appURL == "" {
			appURL = "http://localhost:3000"
		}
		redirectURL = appURL + "/auth/oidc/callback"
	}

	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %s: %w", issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDCProvider{
		Provider:     provider,
		Verifier:     verifier,
		OAuth2Config: oauth2Config,
		Issuer:       issuer,
	}, nil
}

func (p *OIDCProvider) Enabled() bool {
	return p != nil && p.Provider != nil
}

func ProviderName() string {
	if name := os.Getenv("OIDC_PROVIDER_NAME"); name != "" {
		return name
	}
	return "SSO"
}

func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func SetOIDCCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int((15 * time.Minute).Seconds()),
		Path:     "/",
		Secure:   isSecureCookie(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func GetAndClearOIDCCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})
	return c.Value, nil
}
