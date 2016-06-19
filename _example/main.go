package main

import (
	"fmt"
	"net/http"

	"github.com/goware/jwtauth"
	"github.com/pressly/chi"
	"golang.org/x/net/context"
)

var TokenAuth *jwtauth.JwtAuth

func init() {
	TokenAuth = jwtauth.New("HS256", []byte("secret"), nil)
}

func main() {
	r := router()
	http.ListenAndServe(":3000", r)
}

func router() http.Handler {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(TokenAuth.Verifier)

		// Handle valid / invalid tokens. In this example, we use
		// the provided authenticator middleware, but you can write your
		// own very easily, look at the Authenticator method in jwtauth.go
		// and tweak it, its not scary.
		r.Use(jwtauth.Authenticator)

		r.Get("/admin", func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			token := ctx.Value("jwt").(*jwtauth.Token)
			claims := token.Claims

			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	return r
}
