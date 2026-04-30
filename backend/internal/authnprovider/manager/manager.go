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
	"encoding/json"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/authnprovider/provider"
	"github.com/asgardeo/thunder/internal/entityprovider"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/i18n/core"
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

// AuthenticateUser authenticates with the underlying provider and returns an updated AuthUser.
func (m *authnProviderManager) AuthenticateUser(ctx context.Context, identifiers, credentials map[string]interface{},
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.AuthnMetadata,
	authUser AuthUser) (AuthUser, *serviceerror.ServiceError) {
	if len(authUser.authHistory) > 0 && !authUser.IsAuthenticated() {
		m.logger.Error("AuthenticateUser called while in a non-authenticated state from previous authentication step")
		return AuthUser{}, &serviceerror.InternalServerError
	}

	result, svcErr := m.provider.Authenticate(ctx, identifiers, credentials, metadata)
	if svcErr != nil {
		if svcErr.Type == serviceerror.ServerErrorType {
			m.logger.Error("provider returned server error during authentication",
				log.String("error", svcErr.ErrorDescription.DefaultValue))
			return AuthUser{}, &serviceerror.InternalServerError
		}
		switch svcErr.Code {
		case authnprovidercm.ErrorCodeUserNotFound:
			return AuthUser{}, serviceerror.CustomServiceError(ErrorUserNotFound, core.I18nMessage{
				Key:          "error.authnprovider.user_not_found_description",
				DefaultValue: svcErr.ErrorDescription.DefaultValue,
			})
		case authnprovidercm.ErrorCodeInvalidRequest:
			return AuthUser{}, serviceerror.CustomServiceError(ErrorInvalidRequest, core.I18nMessage{
				Key:          "error.authnprovider.invalid_request_description",
				DefaultValue: svcErr.ErrorDescription.DefaultValue,
			})
		default:
			return AuthUser{}, serviceerror.CustomServiceError(ErrorAuthenticationFailed, core.I18nMessage{
				Key:          "error.authnprovider.authentication_failed_description",
				DefaultValue: svcErr.ErrorDescription.DefaultValue,
			})
		}
	}

	authResult := AuthResult{
		isVerified: true,
		authType:   result.AuthType,
		token:      result.Token,
	}

	if result.IsExistingUser {
		authResult.localUserState = ProviderUserStateExists
	} else if result.IsAmbiguousUser {
		authResult.localUserState = ProviderUserStateAmbiguous
	} else {
		authResult.localUserState = ProviderUserStateNotExists
	}

	attributesResult := make(map[string]interface{})
	for k, v := range result.AttributesResponse.Attributes {
		attributesResult[k] = v.Value
	}

	if result.IsExistingUser {
		authResult.providerAttributes = attributesResult
		authResult.isProviderAttributeValuesIncluded = result.IsAttributeValuesIncluded
	} else if result.IsAttributeValuesIncluded {
		// if no existing user, included attributes are attributes resolved at runtime
		// eg: userinfo from federated auth
		//     mobile number from sms OTP auth
		authResult.runtimeAttributes = attributesResult
		if result.ExternalSub != "" {
			authResult.runtimeAttributes["sub"] = result.ExternalSub
		}
	}

	if svcErr := m.validateIdentityField(
		"provider returned a different user ID than the one already set in authUser",
		"existingUserID", "newUserID", authUser.userID, result.UserID, true); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.userID = result.UserID

	if svcErr := m.validateIdentityField(
		"provider returned a different user type than the one already set in authUser",
		"existingUserType", "newUserType", authUser.userType, result.UserType, false); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.userType = result.UserType

	if svcErr := m.validateIdentityField(
		"provider returned a different OUID than the one already set in authUser",
		"existingOUID", "newOUID", authUser.ouID, result.OUID, false); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.ouID = result.OUID

	authUser.authHistory = append(authUser.authHistory, &authResult)

	return authUser, nil
}

// AuthenticateResolvedUser is used to complete the authentication of a user whose last authentication step resulted
// in a non-existing local user.
// i.e. user was ambigous or did not exist at the time AuthenticateUser was called, but has since been resolved to
// an existing user (e.g. through user provisioning or disambiguation).
func (m *authnProviderManager) AuthenticateResolvedUser(ctx context.Context, resolvedUser *entityprovider.Entity,
	authUser AuthUser) (AuthUser, *serviceerror.ServiceError) {
	if authUser.getLastAuthResult() == nil || authUser.IsAuthenticated() {
		authUser.authHistory = append(authUser.authHistory, &AuthResult{})
	}
	lastAuthResult := authUser.getLastAuthResult()

	if lastAuthResult.localUserState == ProviderUserStateExists && !lastAuthResult.isVerified {
		m.logger.Error("AuthenticateResolvedUser called while in a non verified state from previous step")
		return AuthUser{}, &serviceerror.InternalServerError
	}

	if svcErr := m.validateIdentityField(
		"resolved user has a different user ID than the one already set in authUser",
		"existingUserID", "newUserID", authUser.userID, resolvedUser.ID, true); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.userID = resolvedUser.ID

	if svcErr := m.validateIdentityField(
		"resolved user has a different user type than the one already set in authUser",
		"existingUserType", "newUserType", authUser.userType, resolvedUser.Type, false); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.userType = resolvedUser.Type

	if svcErr := m.validateIdentityField(
		"resolved user has a different OUID than the one already set in authUser",
		"existingOUID", "newOUID", authUser.ouID, resolvedUser.OUID, false); svcErr != nil {
		return AuthUser{}, svcErr
	}
	authUser.ouID = resolvedUser.OUID

	lastAuthResult.localUserState = ProviderUserStateExists

	if resolvedUser.Attributes != nil {
		// populate lastAuthResult.attributes by using attributes from resolved user
		var resolvedUserAttributes map[string]interface{}
		if err := json.Unmarshal(resolvedUser.Attributes, &resolvedUserAttributes); err != nil {
			m.logger.Error("failed to unmarshal resolved user attributes", log.String("error", err.Error()))
			return AuthUser{}, &serviceerror.InternalServerError
		}
		lastAuthResult.providerAttributes = resolvedUserAttributes
		lastAuthResult.isProviderAttributeValuesIncluded = true
	} else {
		lastAuthResult.token = resolvedUser.ID
	}

	return authUser, nil
}

func (m *authnProviderManager) AuthenticateForRegistration(ctx context.Context, credentialType string,
	authUser AuthUser) (AuthUser, *serviceerror.ServiceError) {
	// TODO: this should also go through authn provider.

	if credentialType != authnprovidercm.AuthTypePasskey && credentialType != authnprovidercm.AuthTypeCredentials {
		m.logger.Error("unsupported credential type for registration authentication",
			log.String("credentialType", credentialType))
		return AuthUser{}, &serviceerror.InternalServerError
	}

	if authUser.getLastAuthResult() == nil || authUser.IsAuthenticated() {
		authUser.authHistory = append(authUser.authHistory, &AuthResult{})
	}
	lastAuthResult := authUser.getLastAuthResult()

	if lastAuthResult.localUserState != ProviderUserStateExists && lastAuthResult.isVerified {
		m.logger.Error("AuthenticateResolvedUser called while in a unresolved provider user state from previous step")
		return AuthUser{}, &serviceerror.InternalServerError
	}

	lastAuthResult.authType = credentialType
	lastAuthResult.isVerified = true

	return authUser, nil
}

// GetUserAvailableAttributes returns the cached attributes for the default provider without making a provider call.
func (m *authnProviderManager) GetUserAvailableAttributes(ctx context.Context,
	authUser AuthUser) (*authnprovidercm.AttributesResponse, *serviceerror.ServiceError) {
	result := &authnprovidercm.AttributesResponse{
		Attributes: make(map[string]*authnprovidercm.AttributeResponse),
	}

	// runtime attributes have a lower precedence than provider attributes in attribute conflict resolution.
	for _, authResult := range authUser.authHistory {
		for attrName, attrValue := range authResult.runtimeAttributes {
			result.Attributes[attrName] = &authnprovidercm.AttributeResponse{Value: attrValue}
		}
	}
	for _, authResult := range authUser.authHistory {
		for attrName, attrValue := range authResult.providerAttributes {
			result.Attributes[attrName] = &authnprovidercm.AttributeResponse{Value: attrValue}
		}
	}

	return result, nil
}

// GetUserAttributes returns attributes for the user, fetching from the provider if not already cached.
func (m *authnProviderManager) GetUserAttributes(ctx context.Context,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata,
	authUser AuthUser) (AuthUser, *authnprovidercm.AttributesResponse, *serviceerror.ServiceError) {
	// TODO: we do not preserve attribute verification data. need to improve this.

	result := &authnprovidercm.AttributesResponse{
		Attributes: make(map[string]*authnprovidercm.AttributeResponse),
	}

	// runtime attributes have a lower precedence than provider attributes in attribute conflict resolution.
	for _, authResult := range authUser.authHistory {
		for attrName, attrValue := range authResult.runtimeAttributes {
			result.Attributes[attrName] = &authnprovidercm.AttributeResponse{Value: attrValue}
		}
	}

	for _, authResult := range authUser.authHistory {
		if !authResult.isProviderAttributeValuesIncluded {
			authResult.providerAttributes = make(map[string]interface{})

			fetchedAttributes, svcErr := m.provider.GetAttributes(ctx, authResult.token, requestedAttributes, metadata)
			if svcErr != nil {
				if svcErr.Type == serviceerror.ServerErrorType {
					m.logger.Error("provider returned server error while fetching attributes",
						log.String("error", svcErr.ErrorDescription.DefaultValue))
					return AuthUser{}, nil, &serviceerror.InternalServerError
				}
				return AuthUser{}, nil, serviceerror.CustomServiceError(ErrorGetAttributesClientError, core.I18nMessage{
					Key:          "error.authnprovider.get_attributes_client_error_description",
					DefaultValue: svcErr.ErrorDescription.DefaultValue,
				})
			}
			for fetchedAttrName, fetchedAttrResponse := range fetchedAttributes.AttributesResponse.Attributes {
				authResult.providerAttributes[fetchedAttrName] = fetchedAttrResponse.Value
			}
			authResult.isProviderAttributeValuesIncluded = true
		}
		for attrName, attrValue := range authResult.providerAttributes {
			if requestedAttributes == nil || requestedAttributes.Attributes == nil ||
				requestedAttributes.Attributes[attrName] != nil {
				result.Attributes[attrName] = &authnprovidercm.AttributeResponse{Value: attrValue}
			}
		}
	}

	return authUser, result, nil
}

// validateIdentityField checks that a new identity field value does not conflict with an existing one.
// Set masked to true for sensitive fields (e.g. user ID) to redact values in logs.
func (m *authnProviderManager) validateIdentityField(logMsg, existingKey, newKey, existingVal, newVal string,
	masked bool) *serviceerror.ServiceError {
	if newVal != "" && existingVal != "" && existingVal != newVal {
		logField := log.String
		if masked {
			logField = log.MaskedString
		}
		m.logger.Error(logMsg,
			logField(existingKey, existingVal),
			logField(newKey, newVal))
		return serviceerror.CustomServiceError(ErrorAuthenticationFailed, core.I18nMessage{
			Key:          "error.authnprovider.inconsistent_user_identity_description",
			DefaultValue: "authentication failed due to inconsistent user identity information",
		})
	}
	return nil
}
