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

package credentials

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/authn/common"
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/managermock"
)

const (
	testUserID = "user123"
	testToken  = "test_token"
)

type CredentialsAuthnServiceTestSuite struct {
	suite.Suite
	mockAuthnProvider *managermock.AuthnProviderManagerInterfaceMock
	service           CredentialsAuthnServiceInterface
}

func TestCredentialsAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(CredentialsAuthnServiceTestSuite))
}

func (suite *CredentialsAuthnServiceTestSuite) SetupTest() {
	suite.mockAuthnProvider = managermock.NewAuthnProviderManagerInterfaceMock(suite.T())
	suite.service = newCredentialsAuthnService(suite.mockAuthnProvider)
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateSuccess() {
	identifiers := map[string]interface{}{
		"username": "testuser",
	}
	credentials := map[string]interface{}{
		"password": "testpass",
	}

	userID := testUserID
	orgUnit := "test-ou"
	userType := "person"
	userToken := "test-token"

	availableAttributes := &authnprovidercm.AvailableAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataResponse{
			"username": {
				AssuranceMetadataResponse: &authnprovidercm.AssuranceMetadataResponse{
					IsVerified: false,
				},
			},
		},
		Verifications: nil,
	}

	metadata := &authnprovidercm.AuthnMetadata{
		AppMetadata: map[string]interface{}{"key": "value"},
	}

	providerResponse := &authnprovidercm.AuthnResult{
		UserID:              userID,
		UserType:            userType,
		OUID:                orgUnit,
		Token:               userToken,
		AvailableAttributes: availableAttributes,
	}

	suite.mockAuthnProvider.On("Authenticate", mock.Anything, identifiers, credentials, metadata).
		Return(providerResponse, nil)

	result, err := suite.service.Authenticate(context.Background(), identifiers, credentials, metadata)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(userID, result.UserID)
	suite.Equal(orgUnit, result.OUID)
	suite.Equal(userType, result.UserType)
	suite.Equal(userToken, result.Token)
	suite.Equal(availableAttributes, result.AvailableAttributes)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateWithNilMetadata() {
	identifiers := map[string]interface{}{
		"username": "testuser",
	}
	credentials := map[string]interface{}{
		"password": "testpass",
	}

	userID := testUserID
	orgUnit := "test-ou"
	userType := "person"
	userToken := "test-token"

	availableAttributes := &authnprovidercm.AvailableAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataResponse{
			"username": {
				AssuranceMetadataResponse: &authnprovidercm.AssuranceMetadataResponse{
					IsVerified: false,
				},
			},
		},
		Verifications: nil,
	}

	providerResponse := &authnprovidercm.AuthnResult{
		UserID:              userID,
		UserType:            userType,
		OUID:                orgUnit,
		Token:               userToken,
		AvailableAttributes: availableAttributes,
	}

	suite.mockAuthnProvider.On("Authenticate", mock.Anything, identifiers, credentials,
		(*authnprovidercm.AuthnMetadata)(nil)).Return(providerResponse, nil)

	result, err := suite.service.Authenticate(context.Background(), identifiers, credentials, nil)
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(userID, result.UserID)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateFailures() {
	cases := []struct {
		name              string
		identifiers       map[string]interface{}
		credentials       map[string]interface{}
		setupMock         func(m *managermock.AuthnProviderManagerInterfaceMock)
		expectedErrorCode string
	}{
		{
			name:              "EmptyIdentifiers",
			identifiers:       map[string]interface{}{},
			credentials:       map[string]interface{}{"password": "pass"},
			setupMock:         nil,
			expectedErrorCode: ErrorEmptyAttributesOrCredentials.Code,
		},
		{
			name:              "EmptyCredentials",
			identifiers:       map[string]interface{}{"username": "user"},
			credentials:       map[string]interface{}{},
			setupMock:         nil,
			expectedErrorCode: ErrorEmptyAttributesOrCredentials.Code,
		},
		{
			name:        "UserNotFound",
			identifiers: map[string]interface{}{"username": "nonexistent"},
			credentials: map[string]interface{}{"password": "testpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, authnprovidercm.NewError(
						authnprovidercm.ErrorCodeUserNotFound, "User not found", "user not found description"))
			},
			expectedErrorCode: common.ErrorUserNotFound.Code,
		},
		{
			name:        "InvalidCredentials",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "wrongpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, authnprovidercm.NewError(
						authnprovidercm.ErrorCodeAuthenticationFailed, "Invalid credentials",
						"invalid credentials description"))
			},
			expectedErrorCode: ErrorInvalidCredentials.Code,
		},
	}

	for _, tc := range cases {
		suite.T().Run(tc.name, func(t *testing.T) {
			m := managermock.NewAuthnProviderManagerInterfaceMock(t)
			if tc.setupMock != nil {
				tc.setupMock(m)
			}
			svc := newCredentialsAuthnService(m)

			result, err := svc.Authenticate(context.Background(), tc.identifiers, tc.credentials, nil)
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			m.AssertExpectations(t)
		})
	}
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateWithServiceErrors() {
	cases := []struct {
		name               string
		identifiers        map[string]interface{}
		credentials        map[string]interface{}
		setupMock          func(m *managermock.AuthnProviderManagerInterfaceMock)
		expectedErrorCode  string
		expectedErrContain string
	}{
		{
			name:        "AuthnProviderSystemError",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "testpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, authnprovidercm.NewError(
						authnprovidercm.ErrorCodeSystemError, "System error", "Database failure"))
			},
			expectedErrorCode: serviceerror.InternalServerError.Code,
		},
		{
			name:        "AuthnProviderUnknownError",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "testpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("Authenticate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, authnprovidercm.NewError(
						"UNKNOWN_CODE", "Unknown error", "Something went wrong"))
			},
			expectedErrorCode: serviceerror.InternalServerError.Code,
		},
	}

	for _, tc := range cases {
		suite.T().Run(tc.name, func(t *testing.T) {
			m := managermock.NewAuthnProviderManagerInterfaceMock(t)
			if tc.setupMock != nil {
				tc.setupMock(m)
			}
			svc := newCredentialsAuthnService(m)

			result, err := svc.Authenticate(context.Background(), tc.identifiers, tc.credentials, nil)
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			m.AssertExpectations(t)
		})
	}
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesSuccess() {
	token := testToken
	requestedAttributes := &authnprovidercm.RequestedAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataRequest{
			"attr1": nil,
			"attr2": nil,
		},
		Verifications: nil,
	}
	metadata := &authnprovidercm.GetAttributesMetadata{
		AppMetadata: map[string]interface{}{"key": "value"},
		Locale:      "en",
	}

	expectedResult := &authnprovidercm.GetAttributesResult{
		UserID:   "user123",
		UserType: "person",
		OUID:     "ou1",
		AttributesResponse: &authnprovidercm.AttributesResponse{
			Attributes: map[string]*authnprovidercm.AttributeResponse{
				"attr1": {Value: "val1"},
			},
		},
	}

	suite.mockAuthnProvider.On("GetAttributes", mock.Anything, token, requestedAttributes,
		&authnprovidercm.GetAttributesMetadata{
			AppMetadata: metadata.AppMetadata,
			Locale:      metadata.Locale,
		}).Return(expectedResult, nil)

	result, err := suite.service.GetAttributes(context.Background(), token, requestedAttributes, metadata)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(expectedResult.UserID, result.UserID)
	suite.Equal(expectedResult.UserType, result.UserType)
	suite.Equal(expectedResult.OUID, result.OUID)
	suite.Equal(expectedResult.AttributesResponse, result.AttributesResponse)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesWithNilMetadata() {
	token := testToken
	requestedAttributes := &authnprovidercm.RequestedAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataRequest{
			"attr1": nil,
		},
		Verifications: nil,
	}

	expectedResult := &authnprovidercm.GetAttributesResult{
		UserID:   "user123",
		UserType: "person",
		OUID:     "ou1",
		AttributesResponse: &authnprovidercm.AttributesResponse{
			Attributes: map[string]*authnprovidercm.AttributeResponse{
				"attr1": {Value: "val1"},
			},
		},
	}

	suite.mockAuthnProvider.On("GetAttributes", mock.Anything, token, requestedAttributes,
		(*authnprovidercm.GetAttributesMetadata)(nil)).
		Return(expectedResult, nil)

	result, err := suite.service.GetAttributes(context.Background(), token, requestedAttributes, nil)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(expectedResult.UserID, result.UserID)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesFailures() {
	token := testToken
	requestedAttributes := &authnprovidercm.RequestedAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataRequest{
			"attr1": nil,
		},
		Verifications: nil,
	}
	metadata := &authnprovidercm.GetAttributesMetadata{}

	cases := []struct {
		name              string
		setupMock         func()
		expectedErrorCode string
	}{
		{
			name: "InvalidToken",
			setupMock: func() {
				suite.mockAuthnProvider.On("GetAttributes", mock.Anything, token, requestedAttributes, mock.Anything).
					Return(nil, authnprovidercm.NewError(authnprovidercm.ErrorCodeInvalidToken, "Invalid token",
						"Token is expired or invalid"))
			},
			expectedErrorCode: ErrorInvalidToken.Code,
		},
		{
			name: "SystemError",
			setupMock: func() {
				suite.mockAuthnProvider.On("GetAttributes", mock.Anything, token, requestedAttributes, mock.Anything).
					Return(nil, authnprovidercm.NewError(authnprovidercm.ErrorCodeSystemError, "System error",
						"DB connection failed"))
			},
			expectedErrorCode: serviceerror.InternalServerError.Code,
		},
	}

	for _, tc := range cases {
		suite.T().Run(tc.name, func(t *testing.T) {
			suite.mockAuthnProvider = managermock.NewAuthnProviderManagerInterfaceMock(t)
			suite.service = newCredentialsAuthnService(suite.mockAuthnProvider)

			if tc.setupMock != nil {
				tc.setupMock()
			}

			result, err := suite.service.GetAttributes(context.Background(), token, requestedAttributes, metadata)

			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			suite.mockAuthnProvider.AssertExpectations(t)
		})
	}
}
