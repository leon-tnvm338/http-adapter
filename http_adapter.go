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

func (httpAdapter HttpAdapter) writeJsonResponse[TClaims interface{}](ctx *fasthttp.RequestCtx, response interface{}, statusCode int, claims TClaims) {
	parsed, _ := json.Marshal(response)
	ctx.Response.SetStatusCode(statusCode)
	ctx.Response.Header.SetCanonical([]byte("Content-Type"), []byte("application/json"))
	ctx.Response.BodyWriter().Write(parsed)
	httpAdapter.onResponse(response, string(ctx.Request.RequestURI()), string(ctx.Request.Header.Method()), statusCode, claims)
}

func (httpAdapter HttpAdapter) AuthMiddleWare[TClaims interface{}](h http.HandlerFunc, authorize func(claims TClaims) (bool, error)) (result http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := httpAdapter.GetClaims[TClaims](r.Header.Get("Authorization"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorized, err := authorize(claims)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (httpAdapter HttpAdapter) httpJsonAdapter[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		parser := httpInputParser{ctx: ctx}
		var err error

		var claims TClaims
		if requireAuth {
			claims, err = httpAdapter.GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		err = parser.Read(&request)
		if err != nil {
			httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		httpAdapter.writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func (httpAdapter HttpAdapter) httpGetJsonAdapter[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var err error
		var claims TClaims

		if requireAuth {
			claims, err = httpAdapter.GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		values, err := url.ParseQuery(ctx.Request.URI().QueryArgs().String())
		err = decoder.Decode(&request, values)
		if err != nil {
			httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			httpAdapter.writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		httpAdapter.writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func (httpAdapter HttpAdapter) RegisterJsonPostRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](url string,
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) {
	r.POST(url, httpAdapter.httpJsonAdapter(handler, requireAuth))
}

func (httpAdapter HttpAdapter) RegisterJsonGetRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](url string,
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
) {
	r.GET(url, httpAdapter.httpGetJsonAdapter(handler, requireAuth))
}

func RegisterHttpHandlerGet(path string, handler http.Handler) {
	r.GET(path, fasthttpadaptor.NewFastHTTPHandler(handler))
}

type HttpAdapter struct {
	address    string
	secretKey  []byte
	onResponse ResponseHook
}

func (h HttpAdapter) ListenAndServe() {
	fmt.Println("The following routes are being served:")
	fmt.Println()
	for method, routes := range r.List() {
		for _, route := range routes {
			fmt.Println("   - " + method + " " + route)
		}
		fmt.Println()
	}
	fmt.Println("Listening for requests at " + h.address)

	log.Fatal(fasthttp.ListenAndServe(h.address, r.Handler))
}
