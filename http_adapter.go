package http

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"

	"github.com/fasthttp/router"
	"github.com/gorilla/schema"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

var verifyKey []byte

type Handler[TRequest interface{}, TResponse interface{}] struct {
	Handle func(request TRequest, claims LoginClaims) (response TResponse, err error)
}
type LoginClaims struct {
	User_id int
}
type ErrorResponse struct {
	Error string
}
type InputParser interface {
	Read(target interface{}) (err error)
	GetParameter(name string) (param interface{})
	GetClaims() (claims LoginClaims, err error)
}

type ByteController func(InputParser, LoginClaims) (response []byte, statusCode int)
type Controller[TRequest interface{}, TResponse interface{}] func(request TRequest, loginClaims LoginClaims) (response TResponse, err error)

// CounterVec allows adding labels to counters
var httpRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "go-be-template",
		Subsystem: "http",
		Name:      "total_requests",
		Help:      "Total number of HTTP requests by method and status",
	},
	// Define the label names - order matters when setting values
	[]string{"method", "status", "path", "user_email"},
)

/*
The httpAdapter file provides adapter functions used to connect the valyala/fasthttp presentation to the domain layer code (in pkg/).
This structure means we can easily swap out the adapter without changing the internal domain logic.
*/
var r = router.New()
var decoder = schema.NewDecoder()

func writeJsonResponse(ctx *fasthttp.RequestCtx, response interface{}, statusCode int, userId int) {
	parsed, _ := json.Marshal(response)
	log.Println(string(ctx.Request.Header.Method()), string(ctx.Request.RequestURI()), strconv.Itoa(statusCode), strconv.Itoa(userId))
	ctx.Response.SetStatusCode(statusCode)
	ctx.Response.Header.SetCanonical([]byte("Content-Type"), []byte("application/json"))
	ctx.Response.BodyWriter().Write(parsed)
	httpRequestsTotal.WithLabelValues(
		string(ctx.Request.Header.Method()),
		strconv.Itoa(statusCode),
		string(ctx.Request.RequestURI()),
		strconv.Itoa(userId),
	).Inc()
}

func httpJsonAdapter[TRequest interface{}, TResponse interface{}](
	handler Handler[TRequest, TResponse],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		parser := httpInputParser{ctx: ctx}
		var err error

		var claims LoginClaims
		if requireAuth {
			claims, err = parser.GetClaims()
			if err != nil {
				writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, 401, claims.User_id)
				return
			}
		}
		var request TRequest
		err = parser.Read(&request)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, 400, claims.User_id)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, 500, claims.User_id)
			return
		}

		writeJsonResponse(ctx, response, 200, claims.User_id)
	}
}

func httpGetJsonAdapter[TRequest interface{}, TResponse interface{}](
	handler Handler[TRequest, TResponse],
	requireAuth bool,
) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		parser := httpInputParser{ctx: ctx}
		var err error
		var claims LoginClaims

		if requireAuth {
			claims, err = parser.GetClaims()
			if err != nil {
				writeJsonResponse(ctx, ErrorResponse{Error: "Unauthorized."}, 401, claims.User_id)
				return
			}
		}
		var request TRequest
		values, err := url.ParseQuery(ctx.Request.URI().QueryArgs().String())
		err = decoder.Decode(&request, values)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "Wrong parameters."}, 400, claims.User_id)
			return
		}

		response, err := handler.Handle(request, claims)
		if err != nil {
			writeJsonResponse(ctx, ErrorResponse{Error: "A server error has occurred."}, 500, claims.User_id)
			return
		}

		writeJsonResponse(ctx, response, 200, claims.User_id)
	}
}

func httpPdfAdapter(handle func(inputParser InputParser, claims LoginClaims) (response []byte, statusCode int)) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		response, statusCode := handle(httpInputParser{ctx: ctx}, LoginClaims{})
		ctx.Response.SetStatusCode(statusCode)
		ctx.SetContentType("application/pdf")
		ctx.Response.Header.Set("Content-disposition", "attachment")
		log.Println(string(ctx.Request.Header.Method()), ctx.Request.RequestURI(), strconv.Itoa(statusCode))
		ctx.Response.SetBody(response)
	}
}

func RegisterJsonPostRoute[TRequest interface{}, TResponse interface{}](url string,
	handler Handler[TRequest, TResponse],
	requireAuth bool,
) {
	r.POST(url, httpJsonAdapter(handler, requireAuth))
}

func RegisterJsonGetRoute[TRequest interface{}, TResponse interface{}](url string,
	handler Handler[TRequest, TResponse],
	requireAuth bool,
) {
	r.GET(url, httpGetJsonAdapter(handler, requireAuth))
}

func RegisterPdfPostRoute(url string, controller ByteController) {
	r.POST(url, httpPdfAdapter(controller))
}

func ListenAndServe(addr string, secretKey []byte, exposeMetrics bool) {
	verifyKey = secretKey
	prometheus.MustRegister(httpRequestsTotal)
	if exposeMetrics {
		r.GET("/metrics", fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler()))
	}
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
