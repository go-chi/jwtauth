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

	r.Use(TokenAuth.Verifier, jwtauth.Authenticator)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	// wrong token secret and wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	// correct token secret but wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token(TokenSecret, map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", newAuthHeader(), nil); status != 200 && resp != "welcome" {
		t.Fatalf(resp)
	}
}

func TestMore(t *testing.T) {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(TokenAuth.Verifier)

		authenticator := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

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
				next.ServeHTTP(w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("protected"))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome"))
		})
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// sending unauthorized requests
	if status, resp := testRequest(t, ts, "GET", "/admin", nil, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	// wrong token secret and wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}
	// correct token secret but wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token(TokenSecret, map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 && resp != "Unauthorized\n" {
		t.Fatalf(resp)
	}

	h = newAuthHeader((jwtauth.Claims{}).Set("exp", jwtauth.EpochNow()-1000))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 && resp != "expired\n" {
		t.Fatalf(resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 200 && resp != "welcome" {
		t.Fatalf(resp)
	}

	h = newAuthHeader((jwtauth.Claims{}).SetExpiryIn(5 * time.Minute))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 200 && resp != "protected" {
		t.Fatalf(resp)
	}
}

//
// Test helper functions
//

func testRequest(t *testing.T, ts *httptest.Server, method, path string, header http.Header, body io.Reader) (int, string) {
	req, err := http.NewRequest(method, ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}
	defer resp.Body.Close()

	return resp.StatusCode, string(respBody)
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

func newJwt512Token(secret []byte, claims ...jwtauth.Claims) string {
	// use-case: when token is signed with a different alg than expected
	token := jwt.New(jwt.GetSigningMethod("HS512"))
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
