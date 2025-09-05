package rimcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	commonv1 "buf.build/gen/go/rimdesk/common/protocolbuffers/go/rimdesk/common/v1"
	"connectrpc.com/connect"
	"google.golang.org/grpc/metadata"
	"gorm.io/gorm"
)

// PagedResult -------------For Pagination

func (p *PagedResult[T]) GetTotalPages(limit int32) int32 {
	if p == nil || limit <= 0 {
		return 0
	}
	return int32((p.Total + int64(limit) - 1) / int64(limit))
}

func NewPagedResult[T any](total int64, items T) *PagedResult[T] {
	return &PagedResult[T]{
		Items: items,
		Total: total,
	}
}

//-----Scopes for the various scopes for getting the limits in pagination

func WithPaginationScope(pagination *commonv1.PageRequest) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		// Defaults
		page := pagination.GetPage()
		if page <= 0 {
			page = 1
		}

		limit := pagination.GetLimit()
		if limit <= 0 {
			limit = 20
		}

		offset := (page - 1) * limit

		// Apply limit and offset
		db = db.Limit(int(limit)).Offset(int(offset))

		// Sorting
		sort := pagination.GetSort()
		direction := pagination.GetDirection()

		if sort == "" {
			sort = "created_at"
		}

		order := "desc"
		switch direction {
		case commonv1.SortDirection_SORT_DIRECTION_ASC:
			order = "asc"
		case commonv1.SortDirection_SORT_DIRECTION_DESC:
			order = "desc"
		}

		db = db.Order(fmt.Sprintf("%s %s", sort, order))

		return db
	}
}

const (
	// ContextKeyUser is used to store the authenticated user's claims in context.
	ContextKeyUser = "UserClaimsKey"
	// XTenantKey is the metadata key for the company Id header
	XTenantKey = "x-tenant-id"
)

// UserAuthClaims represents the JWT claims structure

func (u UserAuthClaims) String() string {
	jb, _ := json.Marshal(u)
	return string(jb)
}

//Context helper for authentication

//Exceptions

var ErrMissingTenantHeader = connect.NewError(connect.CodeInvalidArgument, errors.New("x-tenant-id is required in the header"))
var ErrFailedParsingTokenClaims = connect.NewError(connect.CodeInvalidArgument, errors.New("token claims could not be parsed"))
var ErrInvalidToken = connect.NewError(connect.CodeUnauthenticated, errors.New(fmt.Sprintf("invalid token")))
var ErrMissingOrInvalidToken = connect.NewError(connect.CodeUnauthenticated, errors.New(fmt.Sprintf("missing or invalid token")))

//Helpers

type grpcRequestHelper struct {
	authenticator Authenticator
}

func (helper grpcRequestHelper) GetAccessToken(request connect.AnyRequest) (string, error) {
	return helper.authenticator.ExtractHeaderToken(request)
}

func (helper grpcRequestHelper) GetUserClaims(ctx context.Context) *UserAuthClaims {
	userClaims := ctx.Value(ContextKeyUser).(*UserAuthClaims)
	return userClaims
}

func (helper grpcRequestHelper) GetTenant(ctx context.Context) (string, error) {
	// Extract metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("could not extract metadata")
	}

	// Check if the X-Company-Id header is present
	companyID := md[XTenantKey]
	if len(companyID) == 0 {
		return "", errors.New("could not extract company id")
	}

	log.Printf("Received X-Company-Id: %s", companyID[0])

	return companyID[0], nil
}

func NewContextHelper(authenticator Authenticator) ContextHelper {
	return &grpcRequestHelper{
		authenticator: authenticator,
	}
}

// Middlewares

// UnaryTokenInterceptor checks and parses JWT tokens and adds claims to context
