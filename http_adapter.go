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

func (adapter httpAdapter) writeJsonResponse[TClaims interface{}](ctx *fasthttp.RequestCtx, response interface{}, statusCode int, claims TClaims) {
	parsed, _ := json.Marshal(response)
	ctx.Response.SetStatusCode(statusCode)
	ctx.Response.Header.SetCanonical([]byte("Content-Type"), []byte("application/json"))
	ctx.Response.BodyWriter().Write(parsed)
	adapter.onResponse(response, string(ctx.Request.RequestURI()), string(ctx.Request.Header.Method()), statusCode, claims)
}

func (adapter httpAdapter) AuthMiddleWare[TClaims interface{}](h http.HandlerFunc, authorize func(claims TClaims) (bool, error)) (result http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := adapter.GetClaims[TClaims](r.Header.Get("Authorization"))
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

func (adapter httpAdapter) handleBodyRequest[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
	authorize func(claims TClaims) (bool, error),
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		parser := httpInputParser{ctx: ctx}
		var err error

		var claims TClaims
		if requireAuth {
			claims, err = adapter.GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
			authorized, err := authorize(claims)
			if err != nil {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
			if !authorized {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		err = parser.Read(&request)
		if err != nil {
			adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			adapter.writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		adapter.writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func (adapter httpAdapter) handleGetRequest[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	handler Handler[TRequest, TResponse, TClaims],
	requireAuth bool,
	authorize func(claims TClaims) (bool, error),
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var err error
		var claims TClaims

		if requireAuth {
			claims, err = adapter.GetClaims[TClaims](string(ctx.Request.Header.Peek("Authorization")))
			if err != nil {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
			authorized, err := authorize(claims)
			if err != nil {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
			if !authorized {
				adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, http.StatusUnauthorized, claims)
				return
			}
		}
		var request TRequest
		values, err := url.ParseQuery(ctx.Request.URI().QueryArgs().String())
		err = adapter.decoder.Decode(&request, values)
		if err != nil {
			adapter.writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, http.StatusBadRequest, claims)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			adapter.writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, http.StatusInternalServerError, claims)
			return
		}

		adapter.writeJsonResponse(ctx, response, http.StatusOK, claims)
	}
}

func authorizeNothing[TClaims interface{}](claims TClaims) (authorized bool, err error) {
	return false, nil
}

func (adapter httpAdapter) RegisterJsonRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	method string,
	url string,
	handler Handler[TRequest, TResponse, TClaims],
) {
	if method == "GET" || method == "DELETE" {
		adapter.router.Handle(method, url, adapter.handleGetRequest(handler, false, authorizeNothing))
	} else {
		adapter.router.Handle(method, url, adapter.handleBodyRequest(handler, false, authorizeNothing))
	}
}

func (adapter httpAdapter) RegisterAuthorizedJsonRoute[TRequest interface{}, TResponse interface{}, TClaims interface{}](
	method string,
	url string,
	handler Handler[TRequest, TResponse, TClaims],
	authorize func(TClaims) (bool, error),
) {
	if method == "GET" || method == "DELETE" {
		adapter.router.Handle(method, url, adapter.handleGetRequest(handler, false, authorize))
	} else {
		adapter.router.Handle(method, url, adapter.handleBodyRequest(handler, false, authorize))
	}
}

func (adapter httpAdapter) RegisterHttpHandlerGet(path string, handler http.Handler) {
	adapter.router.GET(path, fasthttpadaptor.NewFastHTTPHandler(handler))
}

type httpAdapter struct {
	address    string
	secretKey  []byte
	onResponse ResponseHook
	router     *router.Router
	decoder    schema.Decoder
}

func NewHttpAdapter(
	address string,
	secretKey string,
	onResponse ResponseHook,
) (adapter httpAdapter) {
	return httpAdapter{
		address:    address,
		secretKey:  []byte(secretKey),
		onResponse: onResponse,
		router:     router.New(),
		decoder:    *schema.NewDecoder(),
	}
}

func (adapter httpAdapter) ListenAndServe() {
	fmt.Println("The following routes are being served:")
	fmt.Println()
	for method, routes := range adapter.router.List() {
		for _, route := range routes {
			fmt.Println("   - " + method + " " + route)
		}
		fmt.Println()
	}
	fmt.Println("Listening for requests at " + adapter.address)

	log.Fatal(fasthttp.ListenAndServe(adapter.address, adapter.router.Handler))
}
