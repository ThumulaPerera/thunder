/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package externalsvc provides external service abstractions for executors.
package externalsvc

import (
	"context"
	"encoding/json"

	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
)

// Error code constants for external service operations
const (
	ErrorCodeUserNotFound         = "USR-60002"
	ErrorCodeAuthenticationFailed = "USR-60007"
)

// User represents a user in the external service interface.
type User struct {
	ID               string          `json:"id,omitempty"`
	OrganizationUnit string          `json:"organizationUnit,omitempty"`
	Type             string          `json:"type,omitempty"`
	Attributes       json.RawMessage `json:"attributes,omitempty"`
}

// AuthenticateUserRequest represents the request body for authenticating a user.
type AuthenticateUserRequest map[string]interface{}

// AuthenticateUserResponse represents the response body for authenticating a user.
type AuthenticateUserResponse struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	OrganizationUnit string `json:"organizationUnit"`
}

// ExternalSvcInterface defines the interface for external services used by executors.
// This abstraction decouples executors from direct dependencies on internal services.
type ExternalSvcInterface interface {
	// IdentifyUser identifies a user with the given filters.
	// Returns the user ID if found, or an error if not found or if an error occurs.
	IdentifyUser(ctx context.Context, filters map[string]interface{}) (*string, *serviceerror.ServiceError)

	// AuthenticateUser authenticates a user with the given request.
	// Returns authentication response with user ID and basic info, or an error.
	AuthenticateUser(ctx context.Context, request AuthenticateUserRequest) (*AuthenticateUserResponse, *serviceerror.ServiceError)

	// GetUser retrieves a user by ID.
	// Returns the complete user object, or an error if not found.
	GetUser(ctx context.Context, userID string) (*User, *serviceerror.ServiceError)
}
