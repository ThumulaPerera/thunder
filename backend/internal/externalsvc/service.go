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

package externalsvc

import (
	"context"

	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/user"
)

// externalService is a proxy implementation of ExternalSvcInterface that delegates to UserServiceInterface.
type externalService struct {
	userService user.UserServiceInterface
}

// NewExternalService creates a new instance of ExternalSvcInterface.
func NewExternalService(userService user.UserServiceInterface) ExternalSvcInterface {
	return &externalService{
		userService: userService,
	}
}

// IdentifyUser finds a user matching the given identifier attributes.
func (e *externalService) IdentifyUser(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError) {
	return e.userService.IdentifyUser(ctx, attributes)
}

// Authenticate validates the given attributes (identifiers + credentials) and returns the user ID.
func (e *externalService) Authenticate(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError) {
	userRequest := user.AuthenticateUserRequest(attributes)

	userResponse, err := e.userService.AuthenticateUser(ctx, userRequest)
	if err != nil {
		return nil, err
	}

	return &userResponse.ID, nil
}

// GetUser retrieves all non-credential attributes for a user by their unique ID.
func (e *externalService) GetUser(ctx context.Context, userID string) (*User, *serviceerror.ServiceError) {
	userObj, err := e.userService.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:               userObj.ID,
		OrganizationUnit: userObj.OrganizationUnit,
		Type:             userObj.Type,
		Attributes:       userObj.Attributes,
	}, nil
}
