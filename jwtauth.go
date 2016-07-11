package jwtauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrUnauthorized = errors.New("jwtauth: unauthorized token")
	ErrExpired      = errors.New("jwtauth: expired token")
)

type JwtAuth struct {
	signKey   []byte
	verifyKey []byte
	signer    jwt.SigningMethod
	parser    *jwt.Parser
}

// New creates a JwtAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
func New(alg string, signKey []byte, verifyKey []byte) *JwtAuth {
	return &JwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwt.GetSigningMethod(alg),
	}
}

// NewWithParser is the same as New, except it supports custom parser settings
// introduced in ver. 2.4.0 of jwt-go
func NewWithParser(alg string, parser *jwt.Parser, signKey []byte, verifyKey []byte) *JwtAuth {
	return &JwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwt.GetSigningMethod(alg),
		parser:    parser,
	}
}

// Verifier middleware will verify a JWT passed by a client request.
// The Verifier will look for a JWT token from:
// 1. 'jwt' URI query parameter
// 2. 'Authorization: BEARER T' request header
// 3. Cookie 'jwt' value
//
// The verification processes finishes here and sets the token and
// a error in the request context and calls the next handler.
//
// Make sure to have your own handler following the Validator that
// will check the value of the "jwt" and "jwt.err" in the context
// and respond to the client accordingly. A generic Authenticator
// middleware is provided by this package, that will return a 401
// message for all unverified tokens, see jwtauth.Authenticator.
func (ja *JwtAuth) Verifier(next http.Handler) http.Handler {
	return ja.Verify("")(next)
}

func (ja *JwtAuth) Verify(paramAliases ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var tokenStr string
			var err error

			// Get token from query params
			tokenStr = r.URL.Query().Get("jwt")

			// Get token from other query param aliases
			if tokenStr == "" && paramAliases != nil && len(paramAliases) > 0 {
				for _, p := range paramAliases {
					tokenStr = r.URL.Query().Get(p)
					if tokenStr != "" {
						break
					}
				}
			}

			// Get token from authorization header
			if tokenStr == "" {
				bearer := r.Header.Get("Authorization")
				if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
					tokenStr = bearer[7:]
				}
			}

			// Get token from cookie
			if tokenStr == "" {
				cookie, err := r.Cookie("jwt")
				if err == nil {
					tokenStr = cookie.Value
				}
			}

			// Token is required, cya
			if tokenStr == "" {
				err = ErrUnauthorized
			}

			// Verify the token
			token, err := ja.Decode(tokenStr)
			if err != nil {
				switch err.Error() {
				case "token is expired":
					err = ErrExpired
				}

				ctx = ja.SetContext(ctx, token, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if token == nil || !token.Valid || token.Method != ja.signer {
				err = ErrUnauthorized
				ctx = ja.SetContext(ctx, token, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Check expiry via "exp" claim
			if ja.IsExpired(token) {
				err = ErrExpired
				ctx = ja.SetContext(ctx, token, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Valid! pass it down the context to an authenticator middleware
			ctx = ja.SetContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func (ja *JwtAuth) SetContext(ctx context.Context, t *jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, "jwt", t)
	ctx = context.WithValue(ctx, "jwt.err", err)
	return ctx
}

func (ja *JwtAuth) Encode(claims Claims) (t *jwt.Token, tokenString string, err error) {
	t = jwt.New(ja.signer)
	t.Claims = claims
	tokenString, err = t.SignedString(ja.signKey)
	t.Raw = tokenString
	return
}

func (ja *JwtAuth) Decode(tokenString string) (t *jwt.Token, err error) {
	if ja.parser != nil {
		return ja.parser.Parse(tokenString, ja.keyFunc)
	}
	return jwt.Parse(tokenString, ja.keyFunc)
}

func (ja *JwtAuth) keyFunc(t *jwt.Token) (interface{}, error) {
	if ja.verifyKey != nil && len(ja.verifyKey) > 0 {
		return ja.verifyKey, nil
	} else {
		return ja.signKey, nil
	}
}

func (ja *JwtAuth) IsExpired(t *jwt.Token) bool {
	if expv, ok := t.Claims["exp"]; ok {
		var exp int64
		switch v := expv.(type) {
		case float64:
			exp = int64(v)
		case int64:
			exp = v
		case json.Number:
			exp, _ = v.Int64()
		default:
		}

		if exp < EpochNow() {
			return true
		}
	}

	return false
}

// Authenticator is a default authentication middleware to enforce access following
// the Verifier middleware. The Authenticator sends a 401 Unauthorized response for
// all unverified tokens and passes the good ones through. It's just fine until you
// decide to write something similar and customize your client response.
func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if jwtErr, ok := ctx.Value("jwt.err").(error); ok {
			if jwtErr != nil {
				http.Error(w, http.StatusText(401), 401)
				return
			}
		}

		jwtToken, ok := ctx.Value("jwt").(*jwt.Token)
		if !ok || jwtToken == nil || !jwtToken.Valid {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

// Claims is a convenience type to manage a JWT claims hash.
type Claims map[string]interface{}

func (c Claims) Set(k string, v interface{}) Claims {
	c[k] = v
	return c
}

func (c Claims) Get(k string) (interface{}, bool) {
	v, ok := c[k]
	return v, ok
}

// Set issued at ("iat") to specified time in the claims
func (c Claims) SetIssuedAt(tm time.Time) Claims {
	c["iat"] = tm.UTC().Unix()
	return c
}

// Set issued at ("iat") to present time in the claims
func (c Claims) SetIssuedNow() Claims {
	c["iat"] = EpochNow()
	return c
}

// Set expiry ("exp") in the claims and return itself so it can be chained
func (c Claims) SetExpiry(tm time.Time) Claims {
	c["exp"] = tm.UTC().Unix()
	return c
}

// Set expiry ("exp") in the claims to some duration from the present time
// and return itself so it can be chained
func (c Claims) SetExpiryIn(tm time.Duration) Claims {
	c["exp"] = ExpireIn(tm)
	return c
}

// Helper function that returns the NumericDate time value used by the spec
func EpochNow() int64 {
	return time.Now().UTC().Unix()
}

// Helper function to return calculated time in the future for "exp" claim.
func ExpireIn(tm time.Duration) int64 {
	return EpochNow() + int64(tm.Seconds())
}
