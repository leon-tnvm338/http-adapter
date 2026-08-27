package http

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

type httpInputParser struct {
	ctx *fasthttp.RequestCtx
}

func (parser httpInputParser) Read(target interface{}) (err error) {
	err = json.Unmarshal(parser.ctx.Request.Body(), target)
	if err != nil {
		log.Println(err)
	}
	return err
}

func (parser httpInputParser) GetParameter(name string) (param interface{}) {
	param = parser.ctx.UserValue(name)
	return param
}

func getAuthToken(tokenString string) (token string, err error) {
	slicedAuthHeader := strings.Split(tokenString, " ")
	if len(slicedAuthHeader) != 2 {
		return "", errors.New("error: Invalid Auth header")
	}
	return slicedAuthHeader[1], nil
}

type JwtLoginClaims[TClaims interface{}] struct {
	jwt.RegisteredClaims
	LoginClaims TClaims
}

func getClaims[TClaims interface{}](tokenString string, verifyKey string) (claims TClaims, err error) {
	authToken, err := getAuthToken(tokenString)
	jwtClaims := JwtLoginClaims[TClaims]{}
	if err != nil {
		return claims, err
	}
	_, err = jwt.ParseWithClaims(authToken, &jwtClaims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		log.Println(err.Error())
	}
	return claims, err
}

func (adapter httpAdapter) getClaims[TClaims interface{}](tokenString string) (claims TClaims, err error) {
	return getClaims[TClaims](tokenString, string(adapter.secretKey))
}
