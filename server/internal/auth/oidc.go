package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// OIDCProvider 封装标准 OIDC Relying Party。
// OIDC 未配置时为 nil；配置有误时 NewOIDCProvider 返回 error。
type OIDCProvider struct {
	Provider      *oidc.Provider
	Verifier      *oidc.IDTokenVerifier
	OAuth2Config  *oauth2.Config
	Issuer        string
	ClientSecret  string
	UsesHS256     bool // true when provider signs tokens with symmetric HS256
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
		ClientSecret: clientSecret,
		UsesHS256:    providerSupportsHS256(provider),
	}, nil
}

func providerSupportsHS256(provider *oidc.Provider) bool {
	var meta struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return false
	}
	for _, alg := range meta.Algs {
		if alg == "HS256" {
			return true
		}
	}
	return false
}

func (p *OIDCProvider) Enabled() bool {
	return p != nil && p.Provider != nil
}

type OIDCClaims struct {
	Nonce string
	Email string
	Name  string
	Pic   string
}

// VerifyHS256IDToken verifies an HS256-signed ID token using the client secret
// as the HMAC key, then extracts standard claims. Standard go-oidc only supports
// asymmetric algorithms (RS256, ES256) via JWKS, so providers that use HS256 need
// this manual verification path.
func (p *OIDCProvider) VerifyHS256IDToken(ctx context.Context, clientID, rawIDToken, accessToken string) (*OIDCClaims, error) {
	token, err := jwt.Parse(rawIDToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(p.ClientSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("HS256 verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if iss, _ := claims["iss"].(string); iss != p.Issuer {
		return nil, fmt.Errorf("oidc: id token issued by a different provider, expected %q got %q", p.Issuer, iss)
	}

	if aud, ok := claims["aud"]; ok {
		audStr, _ := aud.(string)
		if audStr == "" {
			if arr, ok := aud.([]any); ok && len(arr) > 0 {
				audStr, _ = arr[0].(string)
			}
		}
		if audStr != "" && audStr != clientID {
			return nil, fmt.Errorf("oidc: expected audience %q got %q", clientID, audStr)
		}
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().After(time.Unix(int64(exp), 0)) {
			return nil, &oidc.TokenExpiredError{Expiry: time.Unix(int64(exp), 0)}
		}
	}

	// Dump all claims for debugging NetEase SSO token structure
	if rawClaims, err := json.Marshal(claims); err == nil {
		slog.Info("oidc HS256 token claims", "claims", string(rawClaims))
	}

	oc := &OIDCClaims{
		Nonce: toString(claims["nonce"]),
		Email: toString(claims["email"]),
		Name:  toString(claims["name"]),
		Pic:   toString(claims["picture"]),
	}

	// Some providers (e.g. NetEase SSO) don't include email in the ID token.
	// Fall back to the userinfo endpoint to get it.
	if oc.Email == "" && accessToken != "" {
		oc.Email = fetchEmailFromUserinfo(p, accessToken)
	}

	return oc, nil
}

func toString(v any) string {
	s, _ := v.(string)
	return s
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

func fetchEmailFromUserinfo(p *OIDCProvider, accessToken string) string {
	userInfoURL := p.Provider.UserInfoEndpoint()
	if userInfoURL == "" {
		return ""
	}
	req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		slog.Warn("failed to create userinfo request", "error", err)
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("failed to fetch userinfo", "error", err)
		return ""
	}
	defer resp.Body.Close()

	var info struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Pic   string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		slog.Warn("failed to decode userinfo response", "error", err)
		return ""
	}

	slog.Info("oidc userinfo fallback", "email", info.Email, "name", info.Name)
	return info.Email
}
