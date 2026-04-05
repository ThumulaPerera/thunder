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

package passkeyauthn_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/authn/passkey"
	"github.com/asgardeo/thunder/internal/authn/passkeyauthn"
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/tests/mocks/authn/passkeymock"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/managermock"
)

type PasskeyAuthnServiceTestSuite struct {
	suite.Suite
	mockPasskeyService *passkeymock.PasskeyServiceInterfaceMock
	mockAuthnProvider  *managermock.AuthnProviderManagerInterfaceMock
	service            passkeyauthn.PasskeyAuthnServiceInterface
}

func TestPasskeyAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(PasskeyAuthnServiceTestSuite))
}

func (suite *PasskeyAuthnServiceTestSuite) SetupTest() {
	suite.mockPasskeyService = passkeymock.NewPasskeyServiceInterfaceMock(suite.T())
	suite.mockAuthnProvider = managermock.NewAuthnProviderManagerInterfaceMock(suite.T())
	suite.service = passkeyauthn.Initialize(suite.mockPasskeyService, suite.mockAuthnProvider)
}

// StartRegistration tests

func (suite *PasskeyAuthnServiceTestSuite) TestStartRegistration_DelegatesToUnderlyingService() {
	ctx := context.Background()
	expectedToken := "session-token-123"

	suite.mockPasskeyService.On("StartRegistration", ctx, mock.Anything).
		Return(&passkey.PasskeyRegistrationStartData{SessionToken: expectedToken}, (*serviceerror.ServiceError)(nil))

	data, svcErr := suite.service.StartRegistration(ctx, &passkeyauthn.RegistrationStartRequest{
		UserID:         "user-1",
		RelyingPartyID: "example.com",
	})

	suite.Nil(svcErr)
	suite.Require().NotNil(data)
	suite.Equal(expectedToken, data.SessionToken)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

//nolint:dupl // Similar test structure required for different error scenarios across methods
func (suite *PasskeyAuthnServiceTestSuite) TestStartRegistration_ClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             passkey.ErrorEmptyUserIdentifier.Code,
		Error:            "Empty user identifier",
		ErrorDescription: "Either user ID or username must be provided",
	}

	suite.mockPasskeyService.On("StartRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartRegistration(ctx, &passkeyauthn.RegistrationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorEmptyUserIdentifier.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestStartRegistration_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockPasskeyService.On("StartRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartRegistration(ctx, &passkeyauthn.RegistrationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorInvalidFinishData.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestStartRegistration_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "PSK-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockPasskeyService.On("StartRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartRegistration(ctx, &passkeyauthn.RegistrationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-PSKAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

// FinishRegistration tests

func (suite *PasskeyAuthnServiceTestSuite) TestFinishRegistration_DelegatesToUnderlyingService() {
	ctx := context.Background()
	expectedID := "cred-id-123"

	suite.mockPasskeyService.On("FinishRegistration", ctx, mock.Anything).
		Return(&passkey.PasskeyRegistrationFinishData{CredentialID: expectedID}, (*serviceerror.ServiceError)(nil))

	data, svcErr := suite.service.FinishRegistration(ctx, &passkeyauthn.RegistrationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(svcErr)
	suite.Require().NotNil(data)
	suite.Equal(expectedID, data.CredentialID)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

//nolint:dupl // Similar test structure required for different error scenarios across methods
func (suite *PasskeyAuthnServiceTestSuite) TestFinishRegistration_ClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             passkey.ErrorSessionExpired.Code,
		Error:            "Session expired",
		ErrorDescription: "The session has expired. Please start a new session",
	}

	suite.mockPasskeyService.On("FinishRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationFinishData)(nil), mockErr)

	data, svcErr := suite.service.FinishRegistration(ctx, &passkeyauthn.RegistrationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorSessionExpired.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestFinishRegistration_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockPasskeyService.On("FinishRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationFinishData)(nil), mockErr)

	data, svcErr := suite.service.FinishRegistration(ctx, &passkeyauthn.RegistrationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorInvalidFinishData.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestFinishRegistration_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "PSK-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockPasskeyService.On("FinishRegistration", ctx, mock.Anything).
		Return((*passkey.PasskeyRegistrationFinishData)(nil), mockErr)

	data, svcErr := suite.service.FinishRegistration(ctx, &passkeyauthn.RegistrationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-PSKAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

// StartAuthentication tests

func (suite *PasskeyAuthnServiceTestSuite) TestStartAuthentication_DelegatesToUnderlyingService() {
	ctx := context.Background()
	expectedToken := "session-token-456"

	suite.mockPasskeyService.On("StartAuthentication", ctx, mock.Anything).
		Return(&passkey.PasskeyAuthenticationStartData{SessionToken: expectedToken}, (*serviceerror.ServiceError)(nil))

	data, svcErr := suite.service.StartAuthentication(ctx, &passkeyauthn.AuthenticationStartRequest{
		UserID:         "user-1",
		RelyingPartyID: "example.com",
	})

	suite.Nil(svcErr)
	suite.Require().NotNil(data)
	suite.Equal(expectedToken, data.SessionToken)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

//nolint:dupl // Similar test structure required for different error scenarios across methods
func (suite *PasskeyAuthnServiceTestSuite) TestStartAuthentication_ClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             passkey.ErrorNoCredentialsFound.Code,
		Error:            "No credentials found",
		ErrorDescription: "No credentials found for the user. Please register a credential first",
	}

	suite.mockPasskeyService.On("StartAuthentication", ctx, mock.Anything).
		Return((*passkey.PasskeyAuthenticationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartAuthentication(ctx, &passkeyauthn.AuthenticationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorNoCredentialsFound.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestStartAuthentication_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockPasskeyService.On("StartAuthentication", ctx, mock.Anything).
		Return((*passkey.PasskeyAuthenticationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartAuthentication(ctx, &passkeyauthn.AuthenticationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorInvalidFinishData.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestStartAuthentication_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "PSK-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockPasskeyService.On("StartAuthentication", ctx, mock.Anything).
		Return((*passkey.PasskeyAuthenticationStartData)(nil), mockErr)

	data, svcErr := suite.service.StartAuthentication(ctx, &passkeyauthn.AuthenticationStartRequest{
		RelyingPartyID: "example.com",
	})

	suite.Nil(data)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-PSKAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockPasskeyService.AssertExpectations(suite.T())
}

// FinishAuthentication tests

func (suite *PasskeyAuthnServiceTestSuite) TestFinishAuthentication_DelegatesToAuthnProvider() {
	ctx := context.Background()
	expectedResult := &authnprovidercm.AuthnResult{
		UserID:   "user-123",
		UserType: "person",
		OUID:     "ou-123",
	}

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return(expectedResult, (*serviceerror.ServiceError)(nil))

	result, svcErr := suite.service.FinishAuthentication(ctx, &passkeyauthn.AuthenticationFinishRequest{
		CredentialID:   "cred-id",
		CredentialType: "public-key",
		SessionToken:   "token-123",
	})

	suite.Nil(svcErr)
	suite.Equal(expectedResult, result)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestFinishAuthentication_ClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             authnprovidercm.ErrorCodeAuthenticationFailed,
		Error:            "Authentication failed",
		ErrorDescription: "The passkey assertion was invalid",
	}

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return((*authnprovidercm.AuthnResult)(nil), mockErr)

	result, svcErr := suite.service.FinishAuthentication(ctx, &passkeyauthn.AuthenticationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorAuthenticationFailed.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestFinishAuthentication_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return((*authnprovidercm.AuthnResult)(nil), mockErr)

	result, svcErr := suite.service.FinishAuthentication(ctx, &passkeyauthn.AuthenticationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(passkeyauthn.ErrorAuthenticationFailed.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *PasskeyAuthnServiceTestSuite) TestFinishAuthentication_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "PSK-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return((*authnprovidercm.AuthnResult)(nil), mockErr)

	result, svcErr := suite.service.FinishAuthentication(ctx, &passkeyauthn.AuthenticationFinishRequest{
		SessionToken: "token-123",
	})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-PSKAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}
