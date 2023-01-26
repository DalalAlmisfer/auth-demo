package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"
	"zitadel-v2/config"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/pkg/client/rp"
	"github.com/zitadel/oidc/pkg/oidc"
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
	// generate the code challange and store in a global varibale
	authSetting.CodeVerifier = base64.RawURLEncoding.EncodeToString([]byte(uuid.New().String()))
	codeChallenge := oidc.NewSHACodeChallenge(authSetting.CodeVerifier)
	// build the authrization url
	url := url.Values{}
	url.Set("client_id", authSetting.ClientId)
	url.Set("redirect_uri", authSetting.RedirectUri)
	url.Set("response_type", "code")
	url.Set("scope", "openid")
	url.Set("promot", promot)
	url.Set("code_challenge", codeChallenge)
	url.Set("code_challenge_method", "S256")

	http.Redirect(w, r, fmt.Sprintf("%s?%v", authorizeEndpoint, url.Encode()), http.StatusSeeOther)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	// retrieve the authorization code
	code := r.URL.Query().Get("code")

	provider, err := GetProvider()
	if err != nil {
		fmt.Printf("Error at NewRelyingPartyOIDC, %s \n", err)
	}
	// exchange the authorization code and the code verifier with a token
	t, err := rp.CodeExchange(r.Context(), code, provider, rp.WithCodeVerifier(authSetting.CodeVerifier))
	if err != nil {
		fmt.Println("Error at CodeExchange, ", err)
	}
	// store the token to recognize the user
	SetSession(t, w)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func GetProvider() (rp.RelyingParty, error) {
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	provider, err := rp.NewRelyingPartyOIDC(authSetting.Issuer,
		authSetting.ClientId, authSetting.ClientSecret,
		authSetting.RedirectUri, authSetting.Scopes,
		options...)
	if err != nil {
		return nil, err
	}
	return provider, nil
}
