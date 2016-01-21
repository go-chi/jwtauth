package jwtauth_test

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/goware/jwtauth"
	"github.com/pressly/chi"
	"golang.org/x/net/context"
)

var (
	TokenAuth   *jwtauth.JwtAuth
	TokenSecret = []byte("secretpass")
)

func init() {
	TokenAuth = jwtauth.New("HS256", TokenSecret, nil)
}

//
// Tests
//

func TestSimple(t *testing.T) {
	r := chi.NewRouter()

	r.Use(TokenAuth.Verifier)
	r.Use(jwtauth.Authenticator)

	r.Get("/", func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if resp := testRequest(t, ts, "GET", "/", nil, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if resp := testRequest(t, ts, "GET", "/", h, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if resp := testRequest(t, ts, "GET", "/", h, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	// sending authorized requests
	if resp := testRequest(t, ts, "GET", "/", newAuthHeader(), nil); resp != "welcome" {
		t.Fatalf(resp)
	}
}

func TestMore(t *testing.T) {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(TokenAuth.Verifier)

		authenticator := func(next chi.Handler) chi.Handler {
			return chi.HandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
				if jwtErr, ok := ctx.Value("jwt.err").(error); ok {
					switch jwtErr {
					default:
						http.Error(w, http.StatusText(401), 401)
						return
					case jwtauth.ErrExpired:
						http.Error(w, "expired", 401)
						return
					case jwtauth.ErrUnauthorized:
						http.Error(w, http.StatusText(401), 401)
						return
					case nil:
						// no error
					}
				}

				jwtToken, ok := ctx.Value("jwt").(*jwt.Token)
				if !ok || jwtToken == nil || !jwtToken.Valid {
					http.Error(w, http.StatusText(401), 401)
					return
				}

				// Token is authenticated, pass it through
				next.ServeHTTPC(ctx, w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("protected"))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if resp := testRequest(t, ts, "GET", "/admin", nil, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if resp := testRequest(t, ts, "GET", "/admin", h, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if resp := testRequest(t, ts, "GET", "/admin", h, nil); resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h = newAuthHeader((jwtauth.Claims{}).Set("exp", jwtauth.EpochNow()-1000))
	if resp := testRequest(t, ts, "GET", "/admin", h, nil); resp != "expired\n" {
		t.Fatalf(resp)
	}

	// sending authorized requests
	if resp := testRequest(t, ts, "GET", "/", nil, nil); resp != "welcome" {
		t.Fatalf(resp)
	}

	h = newAuthHeader((jwtauth.Claims{}).SetExpiryIn(5 * time.Minute))
	if resp := testRequest(t, ts, "GET", "/admin", h, nil); resp != "protected" {
		t.Fatalf(resp)
	}
}

//
// Test helper functions
//

func testRequest(t *testing.T, ts *httptest.Server, method, path string, header http.Header, body io.Reader) string {
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return ""
	}

	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return ""
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return ""
	}
	defer resp.Body.Close()

	return string(respBody)
}

func newJwtToken(secret []byte, claims ...jwtauth.Claims) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Claims[k] = v
		}
	}
	tokenStr, err := token.SignedString(secret)
	if err != nil {
		log.Fatal(err)
	}
	return tokenStr
}

func newAuthHeader(claims ...jwtauth.Claims) http.Header {
	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken(TokenSecret, claims...))
	return h
}
