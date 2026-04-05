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

	"github.com/asgardeo/thunder/internal/authn/otp"
	"github.com/asgardeo/thunder/internal/authn/passkey"
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/user"
)

type defaultAuthnProvider struct {
	userSvc        user.UserServiceInterface
	passkeyService passkey.PasskeyServiceInterface
	otpService     otp.OTPAuthnServiceInterface
	logger         *log.Logger
}

// newDefaultAuthnProvider creates a new internal user authn provider.
func newDefaultAuthnProvider(userSvc user.UserServiceInterface,
	passkeyService passkey.PasskeyServiceInterface, otpService otp.OTPAuthnServiceInterface) AuthnProviderInterface {
	return &defaultAuthnProvider{
		userSvc:        userSvc,
		passkeyService: passkeyService,
		otpService:     otpService,
		logger:         log.GetLogger().With(log.String(log.LoggerKeyComponentName, "DefaultAuthnProvider")),
	}
}

// Authenticate authenticates the user using the internal user service.
func (p *defaultAuthnProvider) Authenticate(
	ctx context.Context,
	identifiers, credentials map[string]interface{},
	metadata *authnprovidercm.AuthnMetadata,
) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	if credentials == nil {
		return nil, newClientError(authnprovidercm.ErrorCodeAuthenticationFailed,
			"Credentials are required", "Credentials are required for authentication")
	}

	authenticatedUserID := ""

	if passkeyCredential, ok := credentials["passkey"]; ok {
		passkeyCredential := passkeyCredential.(*passkey.PasskeyAuthenticationFinishRequest)
		authResponse, authErr := p.passkeyService.FinishAuthentication(ctx, passkeyCredential)
		if authErr != nil {
			return nil, newClientError(authnprovidercm.ErrorCodeAuthenticationFailed,
				authErr.Error, authErr.ErrorDescription)
		}
		authenticatedUserID = authResponse.ID
	} else if otpCredential, ok := credentials["otp"]; ok {
		otpCredential := otpCredential.(map[string]interface{})
		sessionToken := otpCredential["sessionToken"].(string)
		otpValue := otpCredential["otp"].(string)
		authResponse, authErr := p.otpService.Authenticate(ctx, sessionToken, otpValue)
		if authErr != nil {
			if authErr.Type == serviceerror.ClientErrorType {
				if authErr.Code == otp.ErrorIncorrectOTP.Code {
					return nil, newClientError(authnprovidercm.ErrorCodeAuthenticationFailed,
						authErr.Error, authErr.ErrorDescription)
				}
				return nil, newClientError(authnprovidercm.ErrorCodeInvalidRequest,
					authErr.Error, authErr.ErrorDescription)
			}
			return nil, p.logAndReturnServerError("OTP authentication failed with server error",
				log.String("error", authErr.Error), log.String("errorDescription", authErr.ErrorDescription))
		}
		authenticatedUserID = authResponse.UserID
	} else {
		authResponse, authErr := p.userSvc.AuthenticateUser(ctx, identifiers, credentials)
		if authErr != nil {
			if authErr.Type == serviceerror.ClientErrorType {
				if authErr.Code == user.ErrorUserNotFound.Code {
					return nil, newClientError(authnprovidercm.ErrorCodeUserNotFound,
						authErr.Error, authErr.ErrorDescription)
				}
				if authErr.Code == user.ErrorAuthenticationFailed.Code {
					return nil, newClientError(authnprovidercm.ErrorCodeAuthenticationFailed,
						authErr.Error, authErr.ErrorDescription)
				}
				return nil, newClientError(authnprovidercm.ErrorCodeInvalidRequest,
					authErr.Error, authErr.ErrorDescription)
			}
			return nil, p.logAndReturnServerError("Basic authentication failed with server error",
				log.String("error", authErr.Error), log.String("errorDescription", authErr.ErrorDescription))
		}
		authenticatedUserID = authResponse.ID
	}

	userResult, getUserErr := p.userSvc.GetUser(ctx, authenticatedUserID, false)
	if getUserErr != nil {
		if getUserErr.Code == user.ErrorUserNotFound.Code {
			return nil, newClientError(authnprovidercm.ErrorCodeUserNotFound,
				getUserErr.Error, getUserErr.ErrorDescription)
		}
		return nil, p.logAndReturnServerError("Failed to get user after authentication",
			log.String("error", getUserErr.Error), log.String("errorDescription", getUserErr.ErrorDescription))
	}

	var attributes map[string]interface{}
	if len(userResult.Attributes) > 0 {
		if err := json.Unmarshal(userResult.Attributes, &attributes); err != nil {
			return nil, p.logAndReturnServerError("Failed to get allowed attributes", log.String("error", err.Error()))
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
		UserID:              authenticatedUserID,
		Token:               authenticatedUserID,
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
) (*authnprovidercm.GetAttributesResult, *serviceerror.ServiceError) {
	userID := token

	userResult, authErr := p.userSvc.GetUser(ctx, userID, false)
	if authErr != nil {
		if authErr.Type == serviceerror.ClientErrorType {
			return nil, newClientError(authnprovidercm.ErrorCodeInvalidToken,
				authErr.Error, authErr.ErrorDescription)
		}
		return nil, p.logAndReturnServerError("Failed to get user attributes",
			log.String("error", authErr.Error), log.String("errorDescription", authErr.ErrorDescription))
	}

	var allAttributes map[string]interface{}
	if len(userResult.Attributes) > 0 {
		if err := json.Unmarshal(userResult.Attributes, &allAttributes); err != nil {
			return nil, p.logAndReturnServerError("Failed to unmarshal user attributes",
				log.String("error", err.Error()))
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

func newClientError(code, msg, desc string) *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             code,
		Error:            msg,
		ErrorDescription: desc,
	}
}

func (p *defaultAuthnProvider) logAndReturnServerError(msg string, fields ...log.Field) *serviceerror.ServiceError {
	p.logger.Error(msg, fields...)
	return &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             authnprovidercm.ErrorCodeSystemError,
		Error:            "System error",
		ErrorDescription: "An internal server error occurred",
	}
}
