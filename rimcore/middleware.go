// Package rimcore provides middleware components for gRPC services including
// authentication, tenant management, logging, CORS handling, and health checking.
package rimcore

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/grpchealth"
	"github.com/beego/beego/v2/core/logs"
	"github.com/rs/cors"
)

// grpcAuthMiddleware implements the Middleware interface providing authentication,
// authorization, logging, and CORS handling for gRPC services.
type grpcAuthMiddleware struct {
	loggR         *logs.BeeLogger
	authenticator Authenticator
	contextHelper ContextHelper
}

// UnaryTenantInterceptor returns a Connect interceptor that extracts and validates
// the tenant ID from the X-Tenant-ID header and adds it to the request context.
// Returns ErrMissingTenantHeader if the tenant ID header is missing.
func (middleware *grpcAuthMiddleware) UnaryTenantInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			tenantID := req.Header().Get(XTenantKey)
			if tenantID == "" {
				return nil, ErrMissingTenantHeader
			}

			newCtx := context.WithValue(ctx, XTenantKey, tenantID)
			return next(newCtx, req)
		}
	}
}

// UnaryTokenInterceptor returns a Connect interceptor that validates authentication tokens
// for all routes except those specified in the routes parameter. It extracts the token from
// the request header, verifies it, parses the claims, and adds the user claims to the context.
// Returns CodeUnauthenticated error if token is missing, invalid, or cannot be verified.
// Returns CodeInternal error if token claims cannot be parsed.
func (middleware *grpcAuthMiddleware) UnaryTokenInterceptor(routes ...string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			fullMethod := req.Spec().Procedure
			if slices.Contains(routes, fullMethod) {
				return next(ctx, req)
			}

			token, err := middleware.authenticator.ExtractHeaderToken(req)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing or invalid token: %v", err))
			}

			idToken, err := middleware.authenticator.GetVerifier().Verify(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %v", err))
			}

			claims := new(UserAuthClaims)
			if err := idToken.Claims(claims); err != nil {
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to parse token claims: %v", err))
			}

			newCtx := context.WithValue(ctx, ContextKeyUser, claims)
			return next(newCtx, req)
		}
	}
}

// LoggingUnaryInterceptor returns a Connect interceptor that logs sanitized gRPC request
// and response data. It logs the method name, sanitized request, duration, and response
// or error information. Sensitive fields are redacted from request logs.
func (middleware *grpcAuthMiddleware) LoggingUnaryInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			fullMethod := request.Spec().Procedure

			sanitizedReq := middleware.sanitizeRequest(request)

			middleware.loggR.Info(
				"gRPC request received | method=%s | request=%v",
				fullMethod,
				sanitizedReq,
			)

			resp, err := next(ctx, request)
			duration := time.Since(start)

			if err != nil {
				middleware.loggR.Error(
					"gRPC request failed | method=%s | duration=%s | error=%v",
					fullMethod,
					duration,
					err,
				)
			} else {
				middleware.loggR.Info(
					"gRPC request completed | method=%s | duration=%s | response=%v",
					fullMethod,
					duration,
					resp,
				)
			}

			return resp, err
		}
	}
}

// CorsMiddleware returns an HTTP handler that wraps the provided handler with CORS
// configuration. It allows all origins, exposes standard Connect headers, and enables
// appropriate methods for gRPC-Web and Connect protocols.
func (middleware *grpcAuthMiddleware) CorsMiddleware(h http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:       []string{"*"},
		AllowedMethods:       connectcors.AllowedMethods(),
		AllowedHeaders:       []string{"*"},
		ExposedHeaders:       connectcors.ExposedHeaders(),
		AllowCredentials:     false,
		OptionsSuccessStatus: 200,
	})
	return c.Handler(h)
}

// HealthChecker returns a static gRPC health checker for the specified service name.
// The checker can be used to report service health status according to the gRPC health
// checking protocol.
func (middleware *grpcAuthMiddleware) HealthChecker(srvName string) *grpchealth.StaticChecker {
	return grpchealth.NewStaticChecker(srvName)
}

// sanitizeRequest masks sensitive fields in the request struct before logging.
// It identifies and redacts common sensitive field names such as password, token,
// secret, apikey, and auth by replacing their values with "[REDACTED]" or zero values.
func (middleware *grpcAuthMiddleware) sanitizeRequest(req interface{}) interface{} {
	sensitiveFields := map[string]struct{}{
		"password": {},
		"token":    {},
		"secret":   {},
		"apikey":   {},
		"apiKey":   {},
		"auth":     {},
	}
	return sanitize(req, sensitiveFields)
}

// sanitize recursively traverses a struct and redacts fields that match sensitive field names.
// String fields are replaced with "[REDACTED]" and other types are set to their zero values.
// Nested structs are recursively sanitized. Returns a sanitized copy of the input value.
func sanitize(v interface{}, sensitiveFields map[string]struct{}) interface{} {
	if v == nil {
		return nil
	}

	rv := reflect.ValueOf(v)
	rt := reflect.TypeOf(v)

	if rv.Kind() == reflect.Ptr && !rv.IsNil() {
		rv = rv.Elem()
		rt = rt.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return v
	}

	copied := reflect.New(rt).Elem()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		value := rv.Field(i)
		fieldName := strings.ToLower(field.Name)

		if !value.CanInterface() {
			continue
		}

		if _, isSensitive := sensitiveFields[fieldName]; isSensitive {
			if field.Type.Kind() == reflect.String {
				copied.Field(i).SetString("[REDACTED]")
			} else {
				copied.Field(i).Set(reflect.Zero(field.Type))
			}
		} else if field.Type.Kind() == reflect.Struct {
			sanitized := sanitize(value.Interface(), sensitiveFields)
			copied.Field(i).Set(reflect.ValueOf(sanitized))
		} else {
			copied.Field(i).Set(value)
		}
	}
	return copied.Addr().Interface()
}

// NewMiddleware creates and returns a new Middleware instance with the provided
// authenticator, logger, and context helper. The returned middleware can be used
// to configure gRPC service interceptors for authentication, logging, and CORS handling.
func NewMiddleware(authenticator Authenticator, logger *logs.BeeLogger, contextHelper ContextHelper) Middleware {
	return &grpcAuthMiddleware{
		loggR:         logger,
		authenticator: authenticator,
		contextHelper: contextHelper,
	}
}
