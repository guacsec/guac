// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
package generated

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/runtime"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Identify the most important dependencies
	// (GET /analysis/dependencies)
	AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams)
	// Health check the server
	// (GET /healthz)
	HealthCheck(w http.ResponseWriter, r *http.Request)
	// Retrieve the dependencies of a package
	// (GET /query/dependencies)
	RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams)
}

// Unimplemented server implementation that returns http.StatusNotImplemented for each endpoint.

type Unimplemented struct{}

// Identify the most important dependencies
// (GET /analysis/dependencies)
func (_ Unimplemented) AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Health check the server
// (GET /healthz)
func (_ Unimplemented) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Retrieve the dependencies of a package
// (GET /query/dependencies)
func (_ Unimplemented) RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// AnalyzeDependencies operation middleware
func (siw *ServerInterfaceWrapper) AnalyzeDependencies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params AnalyzeDependenciesParams

	// ------------- Optional query parameter "PaginationSpec" -------------

	err = runtime.BindQueryParameter("form", true, false, "PaginationSpec", r.URL.Query(), &params.PaginationSpec)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "PaginationSpec", Err: err})
		return
	}

	// ------------- Required query parameter "sort" -------------

	if paramValue := r.URL.Query().Get("sort"); paramValue != "" {

	} else {
		siw.ErrorHandlerFunc(w, r, &RequiredParamError{ParamName: "sort"})
		return
	}

	err = runtime.BindQueryParameter("form", true, true, "sort", r.URL.Query(), &params.Sort)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "sort", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.AnalyzeDependencies(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// HealthCheck operation middleware
func (siw *ServerInterfaceWrapper) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.HealthCheck(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// RetrieveDependencies operation middleware
func (siw *ServerInterfaceWrapper) RetrieveDependencies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params RetrieveDependenciesParams

	// ------------- Optional query parameter "PaginationSpec" -------------

	err = runtime.BindQueryParameter("form", true, false, "PaginationSpec", r.URL.Query(), &params.PaginationSpec)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "PaginationSpec", Err: err})
		return
	}

	// ------------- Required query parameter "purl" -------------

	if paramValue := r.URL.Query().Get("purl"); paramValue != "" {

	} else {
		siw.ErrorHandlerFunc(w, r, &RequiredParamError{ParamName: "purl"})
		return
	}

	err = runtime.BindQueryParameter("form", true, true, "purl", r.URL.Query(), &params.Purl)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "purl", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.RetrieveDependencies(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshalingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshalingParamError) Error() string {
	return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/analysis/dependencies", wrapper.AnalyzeDependencies)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/healthz", wrapper.HealthCheck)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/query/dependencies", wrapper.RetrieveDependencies)
	})

	return r
}

type BadGatewayJSONResponse Error

type BadRequestJSONResponse Error

type InternalServerErrorJSONResponse Error

type PurlListJSONResponse struct {
	// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
	PaginationInfo PaginationInfo `json:"PaginationInfo"`
	PurlList       []Purl         `json:"PurlList"`
}

type AnalyzeDependenciesRequestObject struct {
	Params AnalyzeDependenciesParams
}

type AnalyzeDependenciesResponseObject interface {
	VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error
}

type AnalyzeDependencies200JSONResponse struct{ PurlListJSONResponse }

func (response AnalyzeDependencies200JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies400JSONResponse struct{ BadRequestJSONResponse }

func (response AnalyzeDependencies400JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response AnalyzeDependencies500JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies502JSONResponse struct{ BadGatewayJSONResponse }

func (response AnalyzeDependencies502JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)

	return json.NewEncoder(w).Encode(response)
}

type HealthCheckRequestObject struct {
}

type HealthCheckResponseObject interface {
	VisitHealthCheckResponse(w http.ResponseWriter) error
}

type HealthCheck200JSONResponse string

func (response HealthCheck200JSONResponse) VisitHealthCheckResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependenciesRequestObject struct {
	Params RetrieveDependenciesParams
}

type RetrieveDependenciesResponseObject interface {
	VisitRetrieveDependenciesResponse(w http.ResponseWriter) error
}

type RetrieveDependencies200JSONResponse struct{ PurlListJSONResponse }

func (response RetrieveDependencies200JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies400JSONResponse struct{ BadRequestJSONResponse }

func (response RetrieveDependencies400JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response RetrieveDependencies500JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies502JSONResponse struct{ BadGatewayJSONResponse }

func (response RetrieveDependencies502JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)

	return json.NewEncoder(w).Encode(response)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Identify the most important dependencies
	// (GET /analysis/dependencies)
	AnalyzeDependencies(ctx context.Context, request AnalyzeDependenciesRequestObject) (AnalyzeDependenciesResponseObject, error)
	// Health check the server
	// (GET /healthz)
	HealthCheck(ctx context.Context, request HealthCheckRequestObject) (HealthCheckResponseObject, error)
	// Retrieve the dependencies of a package
	// (GET /query/dependencies)
	RetrieveDependencies(ctx context.Context, request RetrieveDependenciesRequestObject) (RetrieveDependenciesResponseObject, error)
}

type StrictHandlerFunc = strictnethttp.StrictHTTPHandlerFunc
type StrictMiddlewareFunc = strictnethttp.StrictHTTPMiddlewareFunc

type StrictHTTPServerOptions struct {
	RequestErrorHandlerFunc  func(w http.ResponseWriter, r *http.Request, err error)
	ResponseErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	}}
}

func NewStrictHandlerWithOptions(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc, options StrictHTTPServerOptions) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: options}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
	options     StrictHTTPServerOptions
}

// AnalyzeDependencies operation middleware
func (sh *strictHandler) AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams) {
	var request AnalyzeDependenciesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.AnalyzeDependencies(ctx, request.(AnalyzeDependenciesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "AnalyzeDependencies")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(AnalyzeDependenciesResponseObject); ok {
		if err := validResponse.VisitAnalyzeDependenciesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// HealthCheck operation middleware
func (sh *strictHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	var request HealthCheckRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.HealthCheck(ctx, request.(HealthCheckRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HealthCheck")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(HealthCheckResponseObject); ok {
		if err := validResponse.VisitHealthCheckResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// RetrieveDependencies operation middleware
func (sh *strictHandler) RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams) {
	var request RetrieveDependenciesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.RetrieveDependencies(ctx, request.(RetrieveDependenciesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "RetrieveDependencies")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(RetrieveDependenciesResponseObject); ok {
		if err := validResponse.VisitRetrieveDependenciesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}
