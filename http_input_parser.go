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

func (parser httpInputParser) getAuthToken() (token string, err error) {
	slicedAuthHeader := strings.Split(string(parser.ctx.Request.Header.Peek("Authorization")), " ")
	if len(slicedAuthHeader) != 2 {
		return "", errors.New("error: Invalid Auth header")
	}
	return slicedAuthHeader[1], nil
}

type JwtLoginClaims struct {
	jwt.RegisteredClaims
	LoginClaims
}

func (parser httpInputParser) GetClaims() (claims LoginClaims, err error) {
	authToken, err := parser.getAuthToken()
	jwtClaims := JwtLoginClaims{}
	if err != nil {
		return claims, err
	}
	_, err = jwt.ParseWithClaims(authToken, &jwtClaims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		log.Println(err.Error())
	}
	log.Println(jwtClaims.LoginClaims.User_id)
	return claims, err
}
