package config

import (
	"github.com/zitadel/oidc/pkg/client/rp"
)

type OIDC struct {
	Issuer       string
	RedirectUri  string
	ClientId     string
	ClientSecret string
	ResponseType string
	Scopes       []string
	Promot       []string
	Provider     rp.RelyingParty
	CodeVerifier string
}

var Settings = struct {
	Auth OIDC
}{
	Auth: OIDC{
		Issuer:       "http://localhost:8080",
		RedirectUri:  "http://localhost:8000/auth/callback",
		ClientId:     "196586714007928835@auth",
		ClientSecret: "dalalSecretForehtwaa",
		ResponseType: "code",
		Scopes:       []string{"openid", "profile", "email"},
		Promot:       []string{"create", "login"},
	},
}
