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
	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/managermock"
)

const (
	testUserID = "user123"
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

	providerResponse := &authnprovidermgr.AuthnBasicResult{
		UserID:   userID,
		UserType: userType,
		OUID:     orgUnit,
	}

	suite.mockAuthnProvider.On("AuthenticateUser", mock.Anything, identifiers, credentials,
		(*authnprovidercm.RequestedAttributes)(nil), (*authnprovidercm.AuthnMetadata)(nil), mock.Anything).
		Return(authnprovidermgr.AuthUser{}, providerResponse, nil)

	_, result, err := suite.service.Authenticate(context.Background(), identifiers, credentials, nil, nil,
		authnprovidermgr.AuthUser{})
	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(userID, result.UserID)
	suite.Equal(orgUnit, result.OUID)
	suite.Equal(userType, result.UserType)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateWithMetadata() {
	identifiers := map[string]interface{}{
		"username": "testuser",
	}
	credentials := map[string]interface{}{
		"password": "testpass",
	}

	userID := testUserID
	orgUnit := "test-ou"
	userType := "person"

	metadata := &authnprovidercm.AuthnMetadata{
		AppMetadata: map[string]interface{}{"key": "value"},
	}

	providerResponse := &authnprovidermgr.AuthnBasicResult{
		UserID:   userID,
		UserType: userType,
		OUID:     orgUnit,
	}

	suite.mockAuthnProvider.On("AuthenticateUser", mock.Anything, identifiers, credentials,
		(*authnprovidercm.RequestedAttributes)(nil), metadata, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, providerResponse, nil)

	_, result, err := suite.service.Authenticate(context.Background(), identifiers, credentials, nil,
		metadata, authnprovidermgr.AuthUser{})
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
				m.On("AuthenticateUser", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil),
						&serviceerror.ServiceError{
							Type: serviceerror.ClientErrorType, Code: authnprovidermgr.ErrorUserNotFound.Code,
							Error: "User not found", ErrorDescription: "user not found description",
						})
			},
			expectedErrorCode: common.ErrorUserNotFound.Code,
		},
		{
			name:        "InvalidCredentials",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "wrongpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("AuthenticateUser", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil),
						&serviceerror.ServiceError{
							Type: serviceerror.ClientErrorType, Code: authnprovidermgr.ErrorAuthenticationFailed.Code,
							Error: "Invalid credentials", ErrorDescription: "invalid credentials description",
						})
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

			_, result, err := svc.Authenticate(context.Background(), tc.identifiers, tc.credentials, nil, nil,
				authnprovidermgr.AuthUser{})
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			m.AssertExpectations(t)
		})
	}
}

func (suite *CredentialsAuthnServiceTestSuite) TestAuthenticateWithServiceErrors() {
	cases := []struct {
		name              string
		identifiers       map[string]interface{}
		credentials       map[string]interface{}
		setupMock         func(m *managermock.AuthnProviderManagerInterfaceMock)
		expectedErrorCode string
	}{
		{
			name:        "AuthnProviderSystemError",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "testpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("AuthenticateUser", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil),
						&serviceerror.ServiceError{
							Type: serviceerror.ServerErrorType, Code: "AUTHN-MGR-1002",
							Error: "System error", ErrorDescription: "Database failure",
						})
			},
			expectedErrorCode: serviceerror.InternalServerError.Code,
		},
		{
			name:        "AuthnProviderUnknownError",
			identifiers: map[string]interface{}{"username": "testuser"},
			credentials: map[string]interface{}{"password": "testpass"},
			setupMock: func(m *managermock.AuthnProviderManagerInterfaceMock) {
				m.On("AuthenticateUser", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil),
						&serviceerror.ServiceError{
							Type: serviceerror.ServerErrorType, Code: "UNKNOWN_CODE",
							Error: "Unknown error", ErrorDescription: "Something went wrong",
						})
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

			_, result, err := svc.Authenticate(context.Background(), tc.identifiers, tc.credentials, nil, nil,
				authnprovidermgr.AuthUser{})
			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			m.AssertExpectations(t)
		})
	}
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesSuccess() {
	requestedAttributes := &authnprovidercm.RequestedAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataRequest{
			"attr1": nil,
			"attr2": nil,
		},
		Verifications: nil,
	}

	authUser := authnprovidermgr.AuthUser{}

	expectedResult := &authnprovidercm.AttributesResponse{
		Attributes: map[string]*authnprovidercm.AttributeResponse{
			"attr1": {Value: "val1"},
		},
	}

	suite.mockAuthnProvider.
		On("GetUserAttributes", mock.Anything, requestedAttributes, (*authnprovidercm.GetAttributesMetadata)(nil),
			authUser).
		Return(authnprovidermgr.AuthUser{}, expectedResult, nil)

	_, result, err := suite.service.GetAttributes(context.Background(), requestedAttributes, nil, authUser)

	suite.Nil(err)
	suite.NotNil(result)
	suite.Equal(expectedResult.Attributes, result.Attributes)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesWithNilRequestedAttributes() {
	authUser := authnprovidermgr.AuthUser{}

	expectedResult := &authnprovidercm.AttributesResponse{
		Attributes: map[string]*authnprovidercm.AttributeResponse{
			"attr1": {Value: "val1"},
		},
	}

	suite.mockAuthnProvider.On("GetUserAttributes", mock.Anything,
		(*authnprovidercm.RequestedAttributes)(nil), (*authnprovidercm.GetAttributesMetadata)(nil), authUser).
		Return(authnprovidermgr.AuthUser{}, expectedResult, nil)

	_, result, err := suite.service.GetAttributes(context.Background(), nil, nil, authUser)

	suite.Nil(err)
	suite.NotNil(result)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *CredentialsAuthnServiceTestSuite) TestGetAttributesFailures() {
	requestedAttributes := &authnprovidercm.RequestedAttributes{
		Attributes: map[string]*authnprovidercm.AttributeMetadataRequest{
			"attr1": nil,
		},
		Verifications: nil,
	}

	cases := []struct {
		name              string
		setupMock         func()
		expectedErrorCode string
	}{
		{
			name: "ClientError",
			setupMock: func() {
				suite.mockAuthnProvider.
					On("GetUserAttributes", mock.Anything, requestedAttributes, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, nil, &serviceerror.ServiceError{
						Type: serviceerror.ClientErrorType, Code: authnprovidermgr.ErrorGetAttributesClientError.Code,
						Error: "Invalid token", ErrorDescription: "Token is expired or invalid",
					})
			},
			expectedErrorCode: ErrorInvalidToken.Code,
		},
		{
			name: "NotAuthenticated",
			setupMock: func() {
				suite.mockAuthnProvider.
					On("GetUserAttributes", mock.Anything, requestedAttributes, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, nil, &serviceerror.ServiceError{
						Type: serviceerror.ServerErrorType, Code: authnprovidermgr.ErrorNotAuthenticated.Code,
						Error: "Not authenticated", ErrorDescription: "No authenticated user session",
					})
			},
			expectedErrorCode: ErrorNotAuthenticated.Code,
		},
		{
			name: "ProviderDataNotFound",
			setupMock: func() {
				suite.mockAuthnProvider.
					On("GetUserAttributes", mock.Anything, requestedAttributes, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, nil, &serviceerror.ServiceError{
						Type: serviceerror.ServerErrorType, Code: authnprovidermgr.ErrorProviderDataNotFound.Code,
						Error: "Provider data not found", ErrorDescription: "No provider data",
					})
			},
			expectedErrorCode: ErrorProviderDataNotFound.Code,
		},
		{
			name: "SystemError",
			setupMock: func() {
				suite.mockAuthnProvider.
					On("GetUserAttributes", mock.Anything, requestedAttributes, mock.Anything, mock.Anything).
					Return(authnprovidermgr.AuthUser{}, nil, &serviceerror.ServiceError{
						Type: serviceerror.ServerErrorType, Code: "UNKNOWN",
						Error: "System error", ErrorDescription: "DB connection failed",
					})
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

			authUser := authnprovidermgr.AuthUser{}
			_, result, err := suite.service.GetAttributes(context.Background(), requestedAttributes, nil, authUser)

			suite.Nil(result)
			suite.NotNil(err)
			suite.Equal(tc.expectedErrorCode, err.Code)
			suite.mockAuthnProvider.AssertExpectations(t)
		})
	}
}
