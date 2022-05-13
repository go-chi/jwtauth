//
// jwtauth example
//
// Sample output:
//
// [peter@pak ~]$ curl -v http://localhost:3333/
// *   Trying ::1...
// * Connected to localhost (::1) port 3333 (#0)
// > GET / HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.49.1
// > Accept: */*
// >
// < HTTP/1.1 200 OK
// < Date: Tue, 13 Sep 2016 15:53:17 GMT
// < Content-Length: 17
// < Content-Type: text/plain; charset=utf-8
// <
// * Connection #0 to host localhost left intact
// welcome anonymous%
//
//
// [peter@pak ~]$ curl -v http://localhost:3333/admin
// *   Trying ::1...
// * Connected to localhost (::1) port 3333 (#0)
// > GET /admin HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.49.1
// > Accept: */*
// >
// < HTTP/1.1 401 Unauthorized
// < Content-Type: text/plain; charset=utf-8
// < X-Content-Type-Options: nosniff
// < Date: Tue, 13 Sep 2016 15:53:19 GMT
// < Content-Length: 13
// <
// Unauthorized
// * Connection #0 to host localhost left intact
//
//
// [peter@pak ~]$ curl -H"Authorization: BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.PZLMJBT9OIVG2qgp9hQr685oVYFgRgWpcSPmNcw6y7M" -v http://localhost:3333/admin
// *   Trying ::1...
// * Connected to localhost (::1) port 3333 (#0)
// > GET /admin HTTP/1.1
// > Host: localhost:3333
// > User-Agent: curl/7.49.1
// > Accept: */*
// > Authorization: BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.PZLMJBT9OIVG2qgp9hQr685oVYFgRgWpcSPmNcw6y7M
// >
// < HTTP/1.1 200 OK
// < Date: Tue, 13 Sep 2016 15:54:26 GMT
// < Content-Length: 22
// < Content-Type: text/plain; charset=utf-8
// <
// * Connection #0 to host localhost left intact
// protected area. hi 123%
//

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type dynamicTokenAuth struct {
	keySet []byte
}

func (d *dynamicTokenAuth) JWTAuth() (*jwtauth.JWTAuth, error) {
	keySet, err := jwtauth.NewKeySet(d.keySet)
	if err != nil {
		return nil, err
	}
	return keySet, nil
}

var tokenAuth *jwtauth.JWTAuth

func init() {
	tokenAuth = jwtauth.New("HS256", []byte("secret"), nil, jwt.WithAcceptableSkew(30*time.Second))

	// For debugging/example purposes, we generate and print
	// a sample jwt token with claims `user_id:123` here:
	_, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"user_id": 123})
	fmt.Printf("DEBUG: a sample jwt for /admin is %s\n\n", tokenString)
	fmt.Printf("DEBUG: a sample jwt for /rotate is %s\n\n", sampleJWTRotate)
}

func main() {
	addr := ":3333"
	fmt.Printf("Starting server on %v\n", addr)
	http.ListenAndServe(addr, router())
}

func router() http.Handler {
	r := chi.NewRouter()

	// Protected routes
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(tokenAuth))

		// Handle valid / invalid tokens. In this example, we use
		// the provided authenticator middleware, but you can write your
		// own very easily, look at the Authenticator method in jwtauth.go
		// and tweak it, its not scary.
		r.Use(jwtauth.Authenticator(tokenAuth))

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	r.Group(func(r chi.Router) {
		dynamicTokenAuth := dynamicTokenAuth{keySet: keySet}
		// Seek, verify and validate JWT tokens based on keys returned by the callback function
		r.Use(jwtauth.VerifierDynamic(dynamicTokenAuth.JWTAuth))

		// Handle valid / invalid tokens. In this example, we use
		// the provided authenticator middleware, but you can write your
		// own very easily, look at the Authenticator method in jwtauth.go
		// and tweak it, its not scary.
		r.Use(jwtauth.Authenticator)

		r.Get("/rotate", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome anonymous"))
		})
	})

	return r
}

var (
	keySet = []byte(`{
    "keys": [
		{
			"kty": "RSA",
            "alg": "RS256",
            "kid": "kid",
            "use": "sig",
			"n": "rgzO_v14UXJ33MvccKI8aIw3YpknVJbRB-m1z1X4j3gaTmmzmb7_naEd1TOKhF6Z1BGupvAKhCs8uHtp5e1PCrp52kzrjv7nqQfDpdppPZmKpwf-OD_lVgLLuCljB71mX9w7T5vI_WiVknuNhm48y0TJQNslpDZum4E2e0BLKUDRKKlo25foGoDuQN535_Xso861U8KsA80jX37BJplQ6IHewV_bbe04NYTVqaFcmLaZCAzh2f8L1h4xt76Y0xF_u8FXt2-rgcWlz17CtZzxC8ZXNI_92pX8CY5LY2eQf_B_n5Rhd5TQvEIdoI1GNBrcKUI9pMeEC4pErcOGgKGH7w",
			"e": "AQAB"
        }
	]
}`)

	sampleJWTRotate = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.APC4bUOmfbcXjBnZnmyiGBpXqlboTB4Qbh_sqJrgSU5AEQlwzjvDJ79eBlty8h6kfq3i5ffy87s-g82ZoRsHqMjwCIvTOVnoEyDgVu68s9lE32uaA0cc2-hbA13DIBsyIUGjehh9c3h93BrUoUr7n0CHgoKgx2OEw1Bq8vm4EqvmFGF-mr_0qi32uudPy3I15SyP1NJfU0ogQEFUdDHww3c8omDmrTPiGlWZAl9AiBMroDu0nq3UOtC4d5Se-361NEGiZ9J_kHcVWGdoMwsi5KEB0Uf3wAfXK3wcXeRu1pTXYKOV3X3g_2ss6mh65bNMsSx-MZUnQv5v6qZMOxMBUA`
)
