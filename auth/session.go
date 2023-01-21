package auth

import (
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/zitadel/oidc/pkg/oidc"
	"golang.org/x/oauth2"
)

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func SetSession(token *oidc.Tokens, r http.ResponseWriter) {
	value := map[string]string{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(r, cookie)
	}
}

func GetAccessToken(r *http.Request) *oidc.Tokens {
	var accessToken, refreshToken string
	if cookie, err := r.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			accessToken = cookieValue["access_token"]
			refreshToken = cookieValue["refresh_token"]
		}
	}
	if accessToken == "" {
		return nil
	}
	return &oidc.Tokens{
		Token: &oauth2.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}
}
