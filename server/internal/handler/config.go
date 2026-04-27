package handler

import (
	"net/http"
	"os"

	"github.com/multica-ai/multica/server/internal/auth"
)

type AppConfig struct {
	CdnDomain string `json:"cdn_domain"`

	AllowSignup    bool   `json:"allow_signup"`
	GoogleClientID string `json:"google_client_id,omitempty"`

	PosthogKey  string `json:"posthog_key"`
	PosthogHost string `json:"posthog_host"`

	OIDCEnabled      bool   `json:"oidc_enabled"`
	OIDCProviderName string `json:"oidc_provider_name,omitempty"`
}

// GetConfig 是公开路由（无需认证），web 应用在登录前调用此接口决定是否渲染
// Google/SSO 登录按钮及注册 UI。仅添加对匿名调用者安全的字段。
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	config := AppConfig{
		AllowSignup:    os.Getenv("ALLOW_SIGNUP") != "false",
		GoogleClientID: os.Getenv("GOOGLE_CLIENT_ID"),
	}
	if h.Storage != nil {
		config.CdnDomain = h.Storage.CdnDomain()
	}
	if h.OIDC != nil && h.OIDC.Enabled() {
		config.OIDCEnabled = true
		config.OIDCProviderName = auth.ProviderName()
	}

	if v := os.Getenv("ANALYTICS_DISABLED"); v != "true" && v != "1" {
		config.PosthogKey = os.Getenv("POSTHOG_API_KEY")
		config.PosthogHost = os.Getenv("POSTHOG_HOST")
		if config.PosthogHost == "" && config.PosthogKey != "" {
			config.PosthogHost = "https://us.i.posthog.com"
		}
	}

	writeJSON(w, http.StatusOK, config)
}
