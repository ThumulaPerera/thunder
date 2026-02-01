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

// Error code constants for external service operations.
const (
	ErrorCodeUserNotFound         = "EXTSVC-1001"
	ErrorCodeAuthenticationFailed = "EXTSVC-1002"
)

// User represents non-credential user attributes.
type User struct {
	ID               string          `json:"id"`
	OrganizationUnit string          `json:"organizationUnit"`
	Type             string          `json:"type"`
	Attributes       json.RawMessage `json:"attributes"`
}

// ExternalSvcInterface defines the interface for external services used by executors.
// This abstraction decouples executors from direct dependencies on internal services.
type ExternalSvcInterface interface {
	// IdentifyUser finds a user matching the given identifier attributes.
	// Input: map of identifier attributes (e.g., {"username": "john"})
	// Output: unique user ID if found
	// Errors: ErrorCodeUserNotFound if no user matches
	IdentifyUser(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError)

	// Authenticate validates the given attributes (identifiers + credentials).
	// Input: map of attributes including credentials (e.g., {"username": "john", "password": "secret"})
	// Output: unique user ID if authentication succeeds
	// Errors: ErrorCodeUserNotFound, ErrorCodeAuthenticationFailed
	Authenticate(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError)

	// GetUser retrieves all non-credential attributes for a user by their unique ID.
	// Input: unique user ID
	// Output: User with all non-credential attributes
	// Errors: ErrorCodeUserNotFound
	GetUser(ctx context.Context, userID string) (*User, *serviceerror.ServiceError)
}
