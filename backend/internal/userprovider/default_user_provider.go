/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package userprovider

import (
	"context"
	"encoding/json"

	"github.com/asgardeo/thunder/internal/user"
)

type defaultUserProvider struct {
	userSvc user.UserServiceInterface
}

func NewDefaultUserProvider(userSvc user.UserServiceInterface) UserProviderInterface {
	return &defaultUserProvider{
		userSvc: userSvc,
	}
}

func (p *defaultUserProvider) IdentifyUser(filters map[string]interface{}) (*string, *UserProviderError) {
	userID, err := p.userSvc.IdentifyUser(context.Background(), filters)
	if err != nil {
		if err.Code == user.ErrorUserNotFound.Code {
			return nil, NewUserProviderError(ErrorCodeUserNotFound, err.Error, err.ErrorDescription)
		}
		return nil, NewUserProviderError(ErrorCodeSystemError, err.Error, err.ErrorDescription)
	}

	return userID, nil
}

func (p *defaultUserProvider) GetUser(userID string) (*User, *UserProviderError) {
	userResult, err := p.userSvc.GetUser(context.Background(), userID)
	if err != nil {
		if err.Code == user.ErrorUserNotFound.Code {
			return nil, NewUserProviderError(ErrorCodeUserNotFound, err.Error, err.ErrorDescription)
		}
		return nil, NewUserProviderError(ErrorCodeSystemError, err.Error, err.ErrorDescription)
	}

	return &User{
		UserID:     userResult.ID,
		UserType:   userResult.Type,
		OU:         userResult.OrganizationUnit,
		Attributes: json.RawMessage(userResult.Attributes),
	}, nil
}
