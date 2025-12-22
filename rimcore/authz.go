// Package rimcore provides authorization functionality using Casbin for role-based access control (RBAC).
// It implements permission checking and policy enforcement for RPC procedures.
package rimcore

import (
	commonv1 "buf.build/gen/go/rimdesk/common/protocolbuffers/go/rimdesk/common/v1"
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

// authZ implements the AuthZ interface and provides authorization enforcement
// using Casbin. It wraps a Casbin enforcer to check permissions against
// defined policies and resources.
type authZ struct {
	enforcer *casbin.Enforcer
}

// authZResolver implements the ResourceResolver interface and maps RPC procedures
// to their required permissions (resource and action pairs). It is used to determine
// what permissions are needed for a given procedure call.
type authZResolver struct {
	permissions map[string]*commonv1.Permission
}

// Resolve maps an RPC procedure name to its required resource and action permissions.
// It looks up the procedure in the permissions map and returns the associated resource
// and action that are required to execute the procedure.
//
// Parameters:
//   - procedure: the name of the RPC procedure to resolve
//
// Returns:
//   - resource: the name of the resource required for the procedure
//   - action: the action required to be performed on the resource
//   - error: an error if the procedure is not found in the permissions map, nil otherwise
func (a authZResolver) Resolve(procedure string) (string, string, error) {
	p, ok := a.permissions[procedure]
	if !ok {
		return "", "", fmt.Errorf("permission not found for procedure: %s" + procedure)
	}

	return p.Resource, p.Action, nil
}

// HasPermission checks if a user has permission to perform a specific action on a resource.
// It uses the Casbin enforcer to evaluate the authorization policy.
//
// Parameters:
//   - userClaims: the authenticated user's claims containing the user ID
//   - resource: the name of the resource being accessed
//   - action: the action to be performed on the resource
//
// Returns:
//   - true if the user is authorized, false otherwise
func (auth *authZ) HasPermission(userClaims *UserAuthClaims, resource string, action string) (bool, error) {
	allowed, err := auth.enforcer.Enforce(userClaims.ID, resource, action)
	if err != nil {
		return false, fmt.Errorf("failed to enforce policy: %v", err)
	}
	if !allowed {
		return false, fmt.Errorf("user does not have permission to perform action %s on resource %s", action, resource)
	}

	return true, nil
}

// Load initializes the authorization enforcer by loading the model and policies.
// It also enables auto-save and logging features for the enforcer.
//
// Returns:
//   - error if loading the policy fails, nil otherwise
func (auth *authZ) Load() error {
	err := auth.enforcer.LoadModel()
	if err != nil {
		return err
	}

	if err := auth.enforcer.LoadPolicy(); err != nil {
		return err
	}
	auth.enforcer.EnableAutoSave(true)
	auth.enforcer.EnableLog(true)

	return nil
}

// NewAuthZ creates a new authorization instance with the specified model and policy adapter.
//
// Parameters:
//   - model: path to the Casbin model configuration file
//   - adapter: the policy storage adapter for loading and saving policies
//
// Returns:
//   - AuthZ: a new authorization instance
func NewAuthZ(model string, db *gorm.DB) (AuthZ, error) {
	a, err := gormadapter.NewAdapterByDB(db)

	if err != nil {
		return nil, err
	}

	policyEnforcer, err := casbin.NewEnforcer(model, a)
	if err != nil {
		return nil, err
	}

	return &authZ{
		enforcer: policyEnforcer,
	}, nil
}

// NewAuthZResolver creates a new resource resolver that maps procedures to permissions.
//
// Parameters:
//   - permissions: a map of procedure names to their required permissions
//
// Returns:
//   - ResourceResolver: a new resolver instance for mapping procedures to resources and actions
func NewAuthZResolver(permissions map[string]*commonv1.Permission) ResourceResolver {
	return &authZResolver{}
}
