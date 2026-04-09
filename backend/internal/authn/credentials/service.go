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

// Package credentials implements an authentication service for credentials-based authentication.
package credentials

import (
	"context"

	"github.com/asgardeo/thunder/internal/authn/common"
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

const (
	loggerComponentName = "CredentialsAuthnService"
)

// CredentialsAuthnServiceInterface defines the contract for credentials-based authenticator services.
type CredentialsAuthnServiceInterface interface {
	Authenticate(ctx context.Context, identifiers, credentials map[string]interface{},
		requestedAttributes *authnprovidercm.RequestedAttributes,
		metadata *authnprovidercm.AuthnMetadata,
		authUser authnprovidermgr.AuthUser) (
		authnprovidermgr.AuthUser, *authnprovidermgr.AuthnBasicResult, *serviceerror.ServiceError)
	GetAttributes(ctx context.Context,
		requestedAttributes *authnprovidercm.RequestedAttributes,
		metadata *authnprovidercm.GetAttributesMetadata,
		authUser authnprovidermgr.AuthUser) (
		authnprovidermgr.AuthUser, *authnprovidercm.AttributesResponse, *serviceerror.ServiceError)
}

// credentialsAuthnService is the default implementation of CredentialsAuthnServiceInterface.
type credentialsAuthnService struct {
	authnProvider authnprovidermgr.AuthnProviderManagerInterface
	logger        *log.Logger
}

// newCredentialsAuthnService creates a new instance of credentials authenticator service.
func newCredentialsAuthnService(
	authnProvider authnprovidermgr.AuthnProviderManagerInterface) CredentialsAuthnServiceInterface {
	service := &credentialsAuthnService{
		authnProvider: authnProvider,
	}
	common.RegisterAuthenticator(service.getMetadata())
	service.logger = log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName))

	return service
}

func (c *credentialsAuthnService) Authenticate(ctx context.Context, identifiers, credentials map[string]interface{},
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.AuthnMetadata,
	authUser authnprovidermgr.AuthUser) (
	authnprovidermgr.AuthUser, *authnprovidermgr.AuthnBasicResult, *serviceerror.ServiceError) {
	if len(identifiers) == 0 || len(credentials) == 0 {
		return authnprovidermgr.AuthUser{}, nil, &ErrorEmptyAttributesOrCredentials
	}

	newAuthUser, result, err := c.authnProvider.AuthenticateUser(ctx, identifiers, credentials, requestedAttributes,
		metadata, authUser)
	if err != nil {
		switch err.Code {
		case authnprovidermgr.ErrorAuthenticationFailed.Code:
			return authnprovidermgr.AuthUser{}, nil, &ErrorInvalidCredentials
		case authnprovidermgr.ErrorUserNotFound.Code:
			return authnprovidermgr.AuthUser{}, nil, &common.ErrorUserNotFound
		default:
			c.logger.Error("Error occurred while authenticating the user", log.String("errorCode", err.Code),
				log.String("errorDescription", err.ErrorDescription))
			return authnprovidermgr.AuthUser{}, nil, &serviceerror.InternalServerError
		}
	}
	return newAuthUser, result, nil
}

func (c *credentialsAuthnService) GetAttributes(ctx context.Context,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata,
	authUser authnprovidermgr.AuthUser) (authnprovidermgr.AuthUser, *authnprovidercm.AttributesResponse,
	*serviceerror.ServiceError) {
	updatedAuthUser, result, err := c.authnProvider.GetUserAttributes(ctx, requestedAttributes, metadata, authUser)
	if err != nil {
		switch err.Code {
		case authnprovidermgr.ErrorGetAttributesClientError.Code:
			return authnprovidermgr.AuthUser{}, nil, &ErrorInvalidToken
		case authnprovidermgr.ErrorNotAuthenticated.Code:
			return authnprovidermgr.AuthUser{}, nil, &ErrorNotAuthenticated
		case authnprovidermgr.ErrorProviderDataNotFound.Code:
			return authnprovidermgr.AuthUser{}, nil, &ErrorProviderDataNotFound
		default:
			c.logger.Error("Error occurred while getting attributes", log.String("errorCode", err.Code),
				log.String("errorDescription", err.ErrorDescription))
			return authnprovidermgr.AuthUser{}, nil, &serviceerror.InternalServerError
		}
	}
	return updatedAuthUser, result, nil
}

// getMetadata returns the authenticator metadata for credentials authenticator.
func (c *credentialsAuthnService) getMetadata() common.AuthenticatorMeta {
	return common.AuthenticatorMeta{
		Name:    common.AuthenticatorCredentials,
		Factors: []common.AuthenticationFactor{common.FactorKnowledge},
	}
}
