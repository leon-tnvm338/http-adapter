package http

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/fasthttp/router"
	"github.com/gorilla/schema"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

var verifyKey []byte

type Handler[TRequest interface{}, TResponse interface{}, TClaims interface{}] struct {
	Handle func(request TRequest, claims TClaims) (response TResponse, err error)
}
type ErrorResponse struct {
	Error string
}
type InputParser interface {
	Read(target interface{}) (err error)
	GetParameter(name string) (param interface{})
}

type ResponseHook func(response interface{}, url string, method string, statusCode int, claims interface{})

var r = router.New()
var decoder = schema.NewDecoder()

var onResponse ResponseHook

func writeJsonResponse[TClaims interface{}](ctx *fasthttp.RequestCtx, response interface{}, statusCode int, claims TClaims) {
	parsed, _ := json.Marshal(response)
	ctx.Response.SetStatusCode(statusCode)
	ctx.Response.Header.SetCanonical([]byte("Content-Type"), []byte("application/json"))
	ctx.Response.BodyWriter().Write(parsed)
	onResponse(response, string(ctx.Request.RequestURI()), string(ctx.Request.Header.Method()), statusCode, claims)
}

func httpJsonAdapter[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		parser := httpInputParser{ctx: ctx}
		var err error

		var claims TClaims
		if requireAuth {
			claims, err = GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		err = parser.Read(&request)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func httpGetJsonAdapter[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var err error
		var claims TClaims

		if requireAuth {
			claims, err = GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		values, err := url.ParseQuery(ctx.Request.URI().QueryArgs().String())
		err = decoder.Decode(&request, values)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func RegisterJsonPostRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](url string,
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) {
	r.POST(url, httpJsonAdapter(handler, requireAuth))
}

func RegisterJsonGetRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](url string,
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) {
	r.GET(url, httpGetJsonAdapter(handler, requireAuth))
}

func RegisterHttpHandlerGet(path string, handler http.Handler) {
	r.GET(path, fasthttpadaptor.NewFastHTTPHandler(handler))
}

func ListenAndServe(
	addr string,
	secretKey []byte,
	exposeMetrics bool,
	onResponseHook ResponseHook,
) {
	onResponse = onResponseHook
	verifyKey = secretKey
	fmt.Println("The following routes are being served:")
	fmt.Println()
	for method, routes := range r.List() {
		for _, route := range routes {
			fmt.Println("   - " + method + " " + route)
		}
		fmt.Println()
	}
	fmt.Println("Listening for requests at " + addr)

	log.Fatal(fasthttp.ListenAndServe(addr, r.Handler))
}
