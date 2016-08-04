jwtauth - JWT middleware for Go HTTP services
=============================================

The `jwtauth` middleware is a simple way to verify a JWT token from a request
and send the result down the request context (`context.Context`).

In a complete JWT-authentication sequence, you'll first capture the token from
a request, decode it, verify and then validate that is correctly signed and hasn't
expired - the `jwtauth.Verifier` middleware handler takes care of all of that. Next,
it's up to an authentication handler to determine what to do with a valid or invalid
token. The `jwtauth.Authenticator` is a provided authentication middleware to enforce
access following the `Verifier`. The `Authenticator` sends a 401 Unauthorized response
for all unverified tokens and passes the good ones through. You can also copy the
Authenticator and customize it to handle invalid tokens to better fit your flow.

The `Verifier` middleware will look for a JWT token from:

1. 'jwt' URI query parameter
2. 'Authorization: BEARER T' request header
3. Cookie 'jwt' value
4. (optional), use `jwtauth.Verify("state")` for additional query parameter aliases

The verification processes finishes here and sets the token and a error in the request
context and calls the next handler.

Make sure to have your own handler following the Validator that will check the value of
the "jwt" and "jwt.err" in the context and respond to the client accordingly. A generic
Authenticator middleware is provided by this package, that will return a 401 message for
all unverified tokens, see jwtauth.Authenticator.

NOTE: This package has been updated to support the latest version of the
underlying jwt library, github.com/dgrijalva/jwt-go. If you run into problems,
make sure to update to the latest version of jwt-go.

# Usage

```go
package myservice

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/goware/jwtauth"
	"github.com/pressly/chi"
	"golang.org/x/net/context"
)

var TokenAuth *jwtauth.JwtAuth

func init() {
	TokenAuth = jwtauth.New("HS256", []byte("secret"), nil)
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
			token := ctx.Value("jwt").(*jwt.Token)
			claims := token.Claims
			w.Write([]byte(fmt.Printf("protected area. hi %v", claims["user_id"])))
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
```

# LICENSE

MIT
