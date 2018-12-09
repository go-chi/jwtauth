package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type Option func(ja *JWTAuth)

func WithSignKey(key interface{}) Option {
	return func(ja *JWTAuth) {
		ja.signKey = key
	}
}

func WithVerifyKey(key interface{}) Option {
	return func(ja *JWTAuth) {
		ja.verifyKey = key
	}
}

func WithCustomParser(parser *jwt.Parser) Option {
	return func(ja *JWTAuth) {
		ja.parser = parser
	}
}

func WithCustomKeyFunc(fn jwt.Keyfunc) Option {
	return func(ja *JWTAuth) {
		ja.customKeyFunc = fn
	}
}
