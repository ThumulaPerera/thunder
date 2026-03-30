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

// Package provider provides authentication provider implementations.
package provider

import (
	"context"
	"encoding/json"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/user"
)

type defaultAuthnProvider struct {
	userSvc user.UserServiceInterface
}

// newDefaultAuthnProvider creates a new internal user authn provider.
func newDefaultAuthnProvider(userSvc user.UserServiceInterface) AuthnProviderInterface {
	return &defaultAuthnProvider{
		userSvc: userSvc,
	}
}

// Authenticate authenticates the user using the internal user service.
func (p *defaultAuthnProvider) Authenticate(
	ctx context.Context,
	identifiers, credentials map[string]interface{},
	metadata *authnprovidercm.AuthnMetadata,
) (*authnprovidercm.AuthnResult, *authnprovidercm.AuthnProviderError) {
	authResponse, authErr := p.userSvc.AuthenticateUser(ctx, identifiers, credentials)
	if authErr != nil {
		if authErr.Type == serviceerror.ClientErrorType {
			if authErr.Code == user.ErrorUserNotFound.Code {
				return nil, authnprovidercm.NewError(
					authnprovidercm.ErrorCodeUserNotFound, authErr.Error, authErr.ErrorDescription)
			}
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeAuthenticationFailed, authErr.Error, authErr.ErrorDescription)
		}
		return nil, authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, authErr.Error, authErr.ErrorDescription)
	}

	userResult, getUserErr := p.userSvc.GetUser(ctx, authResponse.ID, false)
	if getUserErr != nil {
		if getUserErr.Code == user.ErrorUserNotFound.Code {
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeUserNotFound, getUserErr.Error, getUserErr.ErrorDescription)
		}
		return nil, authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, getUserErr.Error, getUserErr.ErrorDescription)
	}

	var attributes map[string]interface{}
	if len(userResult.Attributes) > 0 {
		if err := json.Unmarshal(userResult.Attributes, &attributes); err != nil {
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeSystemError, "Failed to get allowed attributes", err.Error())
		}
	}

	availableAttributes := &authnprovidercm.AvailableAttributes{
		Attributes:    make(map[string]*authnprovidercm.AttributeMetadataResponse),
		Verifications: make(map[string]*authnprovidercm.VerificationResponse),
	}
	for k := range attributes {
		availableAttributes.Attributes[k] = &authnprovidercm.AttributeMetadataResponse{
			AssuranceMetadataResponse: &authnprovidercm.AssuranceMetadataResponse{
				IsVerified:     false,
				VerificationID: "",
			},
		}
	}

	return &authnprovidercm.AuthnResult{
		UserID:              authResponse.ID,
		Token:               authResponse.ID,
		UserType:            userResult.Type,
		OUID:                userResult.OUID,
		AvailableAttributes: availableAttributes,
	}, nil
}

// GetAttributes retrieves the user attributes using the internal user service.
func (p *defaultAuthnProvider) GetAttributes(
	ctx context.Context,
	token string,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata,
) (*authnprovidercm.GetAttributesResult, *authnprovidercm.AuthnProviderError) {
	userID := token

	userResult, authErr := p.userSvc.GetUser(ctx, userID, false)
	if authErr != nil {
		if authErr.Type == serviceerror.ClientErrorType {
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeInvalidToken, authErr.Error, authErr.ErrorDescription)
		}
		return nil, authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, authErr.Error, authErr.ErrorDescription)
	}

	var allAttributes map[string]interface{}
	if len(userResult.Attributes) > 0 {
		if err := json.Unmarshal(userResult.Attributes, &allAttributes); err != nil {
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeSystemError, "System Error", "Failed to unmarshal user attributes")
		}
	}

	attributesResponse := &authnprovidercm.AttributesResponse{
		Attributes:    make(map[string]*authnprovidercm.AttributeResponse),
		Verifications: make(map[string]*authnprovidercm.VerificationResponse),
	}

	if requestedAttributes != nil && len(requestedAttributes.Attributes) > 0 {
		for attrName := range requestedAttributes.Attributes {
			if val, ok := allAttributes[attrName]; ok {
				attributesResponse.Attributes[attrName] = &authnprovidercm.AttributeResponse{
					Value: val,
					AssuranceMetadataResponse: &authnprovidercm.AssuranceMetadataResponse{
						IsVerified:     false,
						VerificationID: "",
					},
				}
			}
		}
	} else {
		for attrName, val := range allAttributes {
			attributesResponse.Attributes[attrName] = &authnprovidercm.AttributeResponse{
				Value: val,
				AssuranceMetadataResponse: &authnprovidercm.AssuranceMetadataResponse{
					IsVerified:     false,
					VerificationID: "",
				},
			}
		}
	}

	return &authnprovidercm.GetAttributesResult{
		UserID:             userResult.ID,
		UserType:           userResult.Type,
		OUID:               userResult.OUID,
		AttributesResponse: attributesResponse,
	}, nil
}
