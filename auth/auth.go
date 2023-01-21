package auth

import (
	"fmt"
	"net/http"
	"time"
	"zitadel-v2/config"

	"github.com/zitadel/oidc/pkg/client/rp"
)

var (
	authSetting       = config.Settings.Auth
	authorizeEndpoint = "http://localhost:8080/oauth/v2/authorize"
)

func Register(w http.ResponseWriter, r *http.Request) {
	t := GetAccessToken(r)
	if t != nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	OIDCAuth(authSetting.Promot[0], w, r)
}

func Login(w http.ResponseWriter, r *http.Request) {
	t := GetAccessToken(r)
	if t != nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	OIDCAuth(authSetting.Promot[1], w, r)
}

func OIDCAuth(promot string, w http.ResponseWriter, r *http.Request) {
	provider := Prepare()
	codeChallenge, _ := rp.GenerateAndStoreCodeChallenge(w, provider)
	Url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&email&profile&prompt=%s&code_challenge=%s&code_challenge_method=S256",
		authorizeEndpoint, authSetting.ClientId, authSetting.RedirectUri, promot, codeChallenge)
	http.Redirect(w, r, Url, http.StatusSeeOther)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	codeverifier, err := authSetting.Provider.CookieHandler().CheckCookie(r, "pkce")
	if err != nil {
		fmt.Println(" error at CheckCookie, ", err)
	}
	t, err := rp.CodeExchange(r.Context(), code, authSetting.Provider, rp.WithCodeVerifier(codeverifier))
	if err != nil {
		fmt.Println("Error at CodeExchange, ", err)
	}
	SetSession(t, w)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func Prepare() rp.RelyingParty {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	provider, err := rp.NewRelyingPartyOIDC(authSetting.Issuer,
		authSetting.ClientId, authSetting.ClientSecret,
		authSetting.RedirectUri, authSetting.Scopes,
		options...)
	if err != nil {
		fmt.Printf("Error at NewRelyingPartyOIDC, %s \n", err)
	}
	authSetting.Provider = provider
	return provider
}
