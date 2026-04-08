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

package manager

import (
	"context"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/authnprovider/provider"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// authnProviderManager is a proxy struct that implements AuthnProviderManagerInterface by delegating
// to an underlying AuthnProviderInterface.
type authnProviderManager struct {
	provider provider.AuthnProviderInterface
	logger   *log.Logger
}

// newAuthnProviderManager creates a new authnProviderManager.
func newAuthnProviderManager(p provider.AuthnProviderInterface) AuthnProviderManagerInterface {
	return &authnProviderManager{
		provider: p,
		logger:   log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthnProviderManager")),
	}
}

// Authenticate delegates to the underlying provider.
func (m *authnProviderManager) Authenticate(ctx context.Context, identifiers, credentials map[string]interface{},
	metadata *authnprovidercm.AuthnMetadata) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	return m.provider.Authenticate(ctx, identifiers, credentials, metadata)
}

// GetAttributes delegates to the underlying provider.
func (m *authnProviderManager) GetAttributes(ctx context.Context, token string,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata) (
	*authnprovidercm.GetAttributesResult, *serviceerror.ServiceError) {
	return m.provider.GetAttributes(ctx, token, requestedAttributes, metadata)
}

// AuthenticateUser authenticates with the underlying provider and populates authUser with the result.
func (m *authnProviderManager) AuthenticateUser(ctx context.Context, identifiers, credentials map[string]interface{},
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.AuthnMetadata,
	authUser *AuthUser) (*AuthnBasicResult, *serviceerror.ServiceError) {
	result, svcErr := m.provider.Authenticate(ctx, identifiers, credentials, metadata)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ServerErrorType {
			m.logger.Error("provider returned server error during authentication",
				log.String("error", svcErr.ErrorDescription))
			return nil, serviceerror.CustomServiceError(ErrorAuthServerError, svcErr.ErrorDescription)
		}
		return nil, serviceerror.CustomServiceError(ErrorAuthenticationFailed, svcErr.ErrorDescription)
	}
	authUser.setIdentity(result.UserID, result.UserType, result.OUID)
	authUser.setProviderData(defaultProvider, providerData{
		token:                     result.Token,
		attributes:                result.AttributesResponse,
		isAttributeValuesIncluded: result.IsAttributeValuesIncluded,
	})
	return &AuthnBasicResult{
		UserID:   result.UserID,
		OUID:     result.OUID,
		UserType: result.UserType,
	}, nil
}

// GetUserAvailableAttributes returns the cached attributes for the default provider without making a provider call.
func (m *authnProviderManager) GetUserAvailableAttributes(ctx context.Context,
	authUser *AuthUser) (*authnprovidercm.AttributesResponse, *serviceerror.ServiceError) {
	if authUser == nil {
		m.logger.Error("GetUserAvailableAttributes called with nil authUser")
		return nil, &ErrorNotAuthenticated
	}
	data, ok := authUser.getProviderData(defaultProvider)
	if !ok {
		m.logger.Error("GetUserAvailableAttributes: no provider data found for default provider")
		return nil, &ErrorProviderDataNotFound
	}
	return data.attributes, nil
}

// GetUserAttributes returns attributes for the user, fetching from the provider if not already cached.
func (m *authnProviderManager) GetUserAttributes(ctx context.Context,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	authUser *AuthUser) (*authnprovidercm.AttributesResponse, *serviceerror.ServiceError) {
	if authUser == nil {
		m.logger.Error("GetUserAttributes called with nil authUser")
		return nil, &ErrorNotAuthenticated
	}
	data, ok := authUser.getProviderData(defaultProvider)
	if !ok {
		m.logger.Error("GetUserAttributes: no provider data found for default provider")
		return nil, &ErrorProviderDataNotFound
	}
	if data.isAttributeValuesIncluded {
		return data.attributes, nil
	}
	result, svcErr := m.provider.GetAttributes(ctx, data.token, requestedAttributes, nil)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ServerErrorType {
			m.logger.Error("provider returned server error while fetching attributes",
				log.String("error", svcErr.ErrorDescription))
			return nil, serviceerror.CustomServiceError(ErrorGetAttributesFailed, svcErr.ErrorDescription)
		}
		return nil, serviceerror.CustomServiceError(ErrorGetAttributesClientError, svcErr.ErrorDescription)
	}
	authUser.setProviderData(defaultProvider, providerData{
		token:                     data.token,
		attributes:                result.AttributesResponse,
		isAttributeValuesIncluded: true,
	})
	return result.AttributesResponse, nil
}
