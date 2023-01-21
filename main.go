package main

import (
	"log"
	"net/http"
	"zitadel-v2/auth"
)

func main() {
	http.HandleFunc("/login", auth.Login)
	http.HandleFunc("/register", auth.Register)
	http.HandleFunc("/auth/callback", auth.Callback)
	http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		t := auth.GetAccessToken(r)
		if t == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})

	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Println("There was an error listening on port :8000", err)
	}
}
