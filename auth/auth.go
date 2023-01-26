package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
	"zitadel-v2/config"

	"github.com/zitadel/oidc/pkg/client/rp"
)

var (
	authSetting       = config.Settings.Auth
	authorizeEndpoint = "http://localhost:8080/oauth/v2/authorize"
)

func Register(w http.ResponseWriter, r *http.Request) {
	// check if the user has token stored in the cookies (already logedin)
	t := GetAccessToken(r)
	if t != nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	// intit authentication
	OIDCAuth(authSetting.Promot[0], w, r)
}

func Login(w http.ResponseWriter, r *http.Request) {
	// check if the user has token stored in the cookies (already logedin)
	t := GetAccessToken(r)
	if t != nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
	OIDCAuth(authSetting.Promot[1], w, r)
}

func OIDCAuth(promot string, w http.ResponseWriter, r *http.Request) {
	// retrieve the identity provider details
	provider := Prepare()
	// generate the code challange and store the code in a cookie named pkce
	codeChallenge, _ := rp.GenerateAndStoreCodeChallenge(w, provider)
	// build the authrization url
	url := url.Values{}
	url.Set("client_id", authSetting.ClientId)
	url.Set("redirect_uri", authSetting.RedirectUri)
	url.Set("response_type", "code")
	url.Set("scope", "openid&email&profile")
	url.Set("promot", promot)
	url.Set("code_challenge", codeChallenge)
	url.Set("code_challenge_method", "S256")

	http.Redirect(w, r, fmt.Sprintf("%s?%v", authorizeEndpoint, url.Encode()), http.StatusSeeOther)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	// retrieve the authorization code
	code := r.URL.Query().Get("code")
	// retrieve the code challange we stored in OIDCAuth to verify the request
	codeverifier, err := authSetting.Provider.CookieHandler().CheckCookie(r, "ehtwaa")
	if err != nil {
		fmt.Println(" error at CheckCookie, ", err)
	}
	// exchange the authorization code and the code verifier with a token
	t, err := rp.CodeExchange(r.Context(), code, authSetting.Provider, rp.WithCodeVerifier(codeverifier))
	if err != nil {
		fmt.Println("Error at CodeExchange, ", err)
	}
	// store the token to recognize the user
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
