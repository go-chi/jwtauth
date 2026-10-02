package jwtauth_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/transform"
)

var (
	TokenAuthHS256 *jwtauth.JWTAuth
	TokenSecret    = []byte("secretpass")

	TokenAuthRS256 *jwtauth.JWTAuth

	PrivateKeyRS256String = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDsH6T+WrdRLKHEhbhbnItRo7X5tj0xssOSCJUiZbCHr52XftIr
hBD6HxbGaKUEzuaCDYGEcQZZRJ1KHfYmJtXPCz4Zp3qlhjNugvTaZoFtQ8RqiWVY
cHqCY6cmI+3cq2mVrd7MstpXKhC8dZ2MZnzx/zqaeiV21SiwxHed8LmWmQIDAQAB
AoGAff9I0L1hkrxJOg/M133KTe8Y3L4lG07z0wonYmp274CDjGKNDdF0KbPLOGaA
n/czw3Qnh5+0LpBRikpAng0dC06z0YnyzrkoPPawC4s2zJeY3NnajK9IfRAAVlby
cIJVmEL/xF3FFHhCfrJNWd+zthcHxCATJOBpH2pwhb4WLfECQQD/geZ/B6p8WlGb
amHFhBd/hQN6cq63RGujf3ecz5H+h4RqFyycaVr3t8QZBBd3O3jRB9FCcan2IxRa
UoYNGNB9AkEA7JQtfmb0p8cTHiDyV6qb8aNJFWipwQVVMmpaXvfC6Aue5uJiyHnx
iScLsj1ozewCgTvzL7MAsfj0k6qX3c01TQJBAPL2JCdhM8XB4N4Hf+dhHzMcWd1j
Fi6hOjWjrSsI2owNc2Wqmbo2GNF8BlW/ZUz02YLzixJCoVqzqtPkqyHjGcUCQQDk
msrbOeFvvo5arrt+uv21oXMdnOVr/xs0fFCXNBLC53fE4z1RO4SKY5CJy41abpR9
DNERZodlcovjpRTa31CBAkEAw8geqJ1+cfEDZYfJxJigFSwbwoLw6BH+GD4KAEdX
G1u9SGGYP19eC2mpQei4V5MqAYEbb82bqcebhwg8kAReNQ==
-----END RSA PRIVATE KEY-----
`

	PublicKeyRS256String = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDsH6T+WrdRLKHEhbhbnItRo7X5
tj0xssOSCJUiZbCHr52XftIrhBD6HxbGaKUEzuaCDYGEcQZZRJ1KHfYmJtXPCz4Z
p3qlhjNugvTaZoFtQ8RqiWVYcHqCY6cmI+3cq2mVrd7MstpXKhC8dZ2MZnzx/zqa
eiV21SiwxHed8LmWmQIDAQAB
-----END PUBLIC KEY-----
`
)

func init() {
	TokenAuthHS256 = jwtauth.New(jwa.HS256().String(), TokenSecret, nil, jwt.WithAcceptableSkew(30*time.Second))
}

//
// Tests
//

func TestSimple(t *testing.T) {
	r := chi.NewRouter()

	r.Use(
		jwtauth.Verifier(TokenAuthHS256),
		jwtauth.Authenticator(TokenAuthHS256),
	)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	tt := []struct {
		Name          string
		Authorization string
		Status        int
		Resp          string
	}{
		{Name: "empty token", Authorization: "", Status: 401, Resp: "no token found\n"},
		{Name: "wrong token", Authorization: "Bearer asdf", Status: 401, Resp: "token is unauthorized\n"},
		{Name: "wrong secret", Authorization: "Bearer " + newJwtToken([]byte("wrong")), Status: 401, Resp: "token is unauthorized\n"},
		{Name: "wrong secret/alg", Authorization: "Bearer " + newJwt512Token([]byte("wrong")), Status: 401, Resp: "token is unauthorized\n"},
		{Name: "wrong alg", Authorization: "Bearer " + newJwt512Token(TokenSecret, map[string]interface{}{}), Status: 401, Resp: "token is unauthorized\n"},
		{Name: "expired within skew", Authorization: "Bearer " + newJwtToken(TokenSecret, map[string]interface{}{"exp": time.Now().Unix() - 29}), Status: 200, Resp: "welcome"},
		{Name: "expired outside skew", Authorization: "Bearer " + newJwtToken(TokenSecret, map[string]interface{}{"exp": time.Now().Unix() - 31}), Status: 401, Resp: "token is expired\n"},
		{Name: "valid token", Authorization: "Bearer " + newJwtToken(TokenSecret), Status: 200, Resp: "welcome"},
		{Name: "valid Bearer", Authorization: "Bearer " + newJwtToken(TokenSecret, map[string]interface{}{"service": "test"}), Status: 200, Resp: "welcome"},
		{Name: "valid BEARER", Authorization: "BEARER " + newJwtToken(TokenSecret), Status: 200, Resp: "welcome"},
		{Name: "valid bearer", Authorization: "bearer " + newJwtToken(TokenSecret), Status: 200, Resp: "welcome"},
		{Name: "valid claim", Authorization: "Bearer " + newJwtToken(TokenSecret, map[string]interface{}{"service": "test"}), Status: 200, Resp: "welcome"},
		{Name: "invalid bearer_", Authorization: "BEARER_" + newJwtToken(TokenSecret), Status: 401, Resp: "no token found\n"},
		{Name: "invalid bearerx", Authorization: "BEARERx" + newJwtToken(TokenSecret), Status: 401, Resp: "no token found\n"},
	}

	for _, tc := range tt {
		h := http.Header{}
		if tc.Authorization != "" {
			h.Set("Authorization", tc.Authorization)
		}
		status, resp := testRequest(t, ts, "GET", "/", h, nil)
		if status != tc.Status || resp != tc.Resp {
			t.Errorf("test '%s' failed: expected Status: %d %q, got %d %q", tc.Name, tc.Status, tc.Resp, status, resp)
		}
	}
}

func TestSimpleRSA(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	TokenAuthRS256 = jwtauth.New(jwa.RS256().String(), privateKey, publicKey)

	claims := map[string]interface{}{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	_, tokenString, err := TokenAuthRS256.Encode(claims)
	if err != nil {
		t.Fatalf("Failed to encode claims %s\n", err.Error())
	}

	token, err := TokenAuthRS256.Decode(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims := map[string]interface{}{}
	if err := transform.AsMap(token, tokenClaims); err != nil {
		t.Fatalf("Failed to get claims %s\n", err.Error())
	}

	if !reflect.DeepEqual(claims, tokenClaims) {
		t.Fatalf("The decoded claims don't match the original ones\n")
	}
}

func TestSimpleRSAVerifyOnly(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJ2YWwiLCJrZXkyIjoidmFsMiIsImtleTMiOiJ2YWwzIn0.IK0G0Qi_c6N6uHRokHMSHQEeYxoi_T73A4RdEzJIfnbs5kA5hF0UhApSWUMZfsTYFNC2buYvWqbyj2kDdXcStpqTUPENGTKvJi66puwhN16BqEOS-jb7kVyf3vWif7XabY0_5S8H_aeqazaj4FemHvWnywJznuMWJRXWw83edpA"
	claims := map[string]interface{}{
		"key":  "val",
		"key2": "val2",
		"key3": "val3",
	}

	publicKeyBlock, _ := pem.Decode([]byte(PublicKeyRS256String))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	TokenAuthRS256 = jwtauth.New(jwa.RS256().String(), nil, publicKey)

	_, _, err = TokenAuthRS256.Encode(claims)
	if err == nil {
		t.Fatalf("Expecting error when encoding claims without signing key")
	}

	token, err := TokenAuthRS256.Decode(tokenString)
	if err != nil {
		t.Fatalf("Failed to decode token string %s\n", err.Error())
	}

	tokenClaims := map[string]interface{}{}
	if err := transform.AsMap(token, tokenClaims); err != nil {
		t.Fatalf("Failed to get claims %s\n", err.Error())
	}

	if !reflect.DeepEqual(claims, tokenClaims) {
		t.Fatalf("The decoded claims don't match the original ones\n")
	}
}

func TestMore(t *testing.T) {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(TokenAuthHS256))

		authenticator := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, _, err := jwtauth.FromContext(r.Context())

				if err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				if err := jwt.Validate(token); err != nil {
					http.Error(w, jwtauth.ErrorReason(err).Error(), http.StatusUnauthorized)
					return
				}

				// Token is authenticated, pass it through
				next.ServeHTTP(w, r)
			})
		}
		r.Use(authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())

			if err != nil {
				w.Write([]byte(fmt.Sprintf("error! %v", err)))
				return
			}

			w.Write([]byte(fmt.Sprintf("protected, user:%v", claims["user_id"])))
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
	if status, resp := testRequest(t, ts, "GET", "/admin", nil, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}

	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	h.Set("Authorization", "BEARER asdf")
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// wrong token secret and wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token([]byte("wrong"), map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}
	// correct token secret but wrong alg
	h.Set("Authorization", "BEARER "+newJwt512Token(TokenSecret, map[string]interface{}{}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is unauthorized\n" {
		t.Fatal(resp)
	}

	h = newAuthHeader(map[string]interface{}{"exp": jwtauth.EpochNow() - 1000})
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 401 || resp != "token is expired\n" {
		t.Fatal(resp)
	}

	// sending authorized requests
	if status, resp := testRequest(t, ts, "GET", "/", nil, nil); status != 200 || resp != "welcome" {
		t.Fatal(resp)
	}

	h = newAuthHeader((map[string]interface{}{"user_id": 31337, "exp": jwtauth.ExpireIn(5 * time.Minute)}))
	if status, resp := testRequest(t, ts, "GET", "/admin", h, nil); status != 200 || resp != "protected, user:31337" {
		t.Fatal(resp)
	}
}

func TestEncodeClaims(t *testing.T) {
	claims := map[string]interface{}{
		"key1": "val1",
		"key2": 2,
		"key3": time.Now(),
		"key4": []string{"1", "2"},
	}
	claims[jwt.JwtIDKey] = 1
	if _, _, err := TokenAuthHS256.Encode(claims); err == nil {
		t.Fatal("encoding invalid claims succeeded")
	}
	claims[jwt.JwtIDKey] = "123"
	if _, _, err := TokenAuthHS256.Encode(claims); err != nil {
		t.Fatalf("unexpected error encoding valid claims: %v", err)
	}
}

func TestTokenExpiration(t *testing.T) {
	// 1. Token without explicit expiry claim does not expire
	claimsNoExp := map[string]interface{}{"user_id": 1}
	_, tokenStringNoExp, err := TokenAuthHS256.Encode(claimsNoExp)
	if err != nil {
		t.Fatalf("unexpected error encoding token without expiry: %v", err)
	}
	tok, err := jwtauth.VerifyToken(TokenAuthHS256, tokenStringNoExp)
	if err != nil {
		t.Fatalf("expected token without expiry claim to validate successfully, got: %v", err)
	}
	if tok == nil {
		t.Fatal("expected token to not be nil")
	}

	// 2. Token with explicit future expiry claim via SetExpiry validates successfully
	claimsFuture := map[string]interface{}{"user_id": 2}
	jwtauth.SetExpiry(claimsFuture, time.Now().Add(1*time.Hour))
	_, tokenStringFuture, err := TokenAuthHS256.Encode(claimsFuture)
	if err != nil {
		t.Fatalf("unexpected error encoding token with future expiry: %v", err)
	}
	tok, err = jwtauth.VerifyToken(TokenAuthHS256, tokenStringFuture)
	if err != nil {
		t.Fatalf("expected token with future expiry to validate, got: %v", err)
	}
	if tok == nil {
		t.Fatal("expected token to not be nil")
	}

	// 3. Token with explicit future expiry claim via SetExpiryIn validates successfully
	claimsFutureIn := map[string]interface{}{"user_id": 3}
	jwtauth.SetExpiryIn(claimsFutureIn, 30*time.Minute)
	_, tokenStringFutureIn, err := TokenAuthHS256.Encode(claimsFutureIn)
	if err != nil {
		t.Fatalf("unexpected error encoding token with SetExpiryIn: %v", err)
	}
	tok, err = jwtauth.VerifyToken(TokenAuthHS256, tokenStringFutureIn)
	if err != nil {
		t.Fatalf("expected token with future expiry duration to validate, got: %v", err)
	}
	if tok == nil {
		t.Fatal("expected token to not be nil")
	}

	// 4. Token with explicit past expiry claim via SetExpiry fails validation with ErrExpired
	claimsExpired := map[string]interface{}{"user_id": 4}
	jwtauth.SetExpiry(claimsExpired, time.Now().Add(-1*time.Hour))
	_, tokenStringExpired, err := TokenAuthHS256.Encode(claimsExpired)
	if err != nil {
		t.Fatalf("unexpected error encoding expired token: %v", err)
	}
	_, err = jwtauth.VerifyToken(TokenAuthHS256, tokenStringExpired)
	if err != jwtauth.ErrExpired {
		t.Fatalf("expected ErrExpired, got: %v", err)
	}

	// 5. Token with past expiry duration via SetExpiryIn fails validation with ErrExpired
	claimsExpiredIn := map[string]interface{}{"user_id": 5}
	jwtauth.SetExpiryIn(claimsExpiredIn, -10*time.Minute)
	_, tokenStringExpiredIn, err := TokenAuthHS256.Encode(claimsExpiredIn)
	if err != nil {
		t.Fatalf("unexpected error encoding expired duration token: %v", err)
	}
	_, err = jwtauth.VerifyToken(TokenAuthHS256, tokenStringExpiredIn)
	if err != jwtauth.ErrExpired {
		t.Fatalf("expected ErrExpired, got: %v", err)
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

	for k, v := range header {
		req.Header.Set(k, v[0])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
		return 0, ""
	}
	defer resp.Body.Close()

	return resp.StatusCode, string(respBody)
}

func newJwtToken(secret []byte, claims ...map[string]interface{}) string {
	token := jwt.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Set(k, v)
		}
	}

	tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func newJwt512Token(secret []byte, claims ...map[string]interface{}) string {
	// use-case: when token is signed with a different alg than expected
	token := jwt.New()
	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Set(k, v)
		}
	}
	tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.HS512(), secret))
	if err != nil {
		log.Fatal(err)
	}
	return string(tokenPayload)
}

func newAuthHeader(claims ...map[string]interface{}) http.Header {
	h := http.Header{}
	h.Set("Authorization", "BEARER "+newJwtToken(TokenSecret, claims...))
	return h
}
