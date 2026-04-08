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
	"testing"

	"github.com/stretchr/testify/suite"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/providermock"
)

type ManagerTestSuite struct {
	suite.Suite
	mockProvider *providermock.AuthnProviderInterfaceMock
	mgr          AuthnProviderManagerInterface
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

func (s *ManagerTestSuite) SetupTest() {
	s.mockProvider = providermock.NewAuthnProviderInterfaceMock(s.T())
	s.mgr = newAuthnProviderManager(s.mockProvider)
}

func (s *ManagerTestSuite) TestAuthenticateUser_Success() {
	authUser := NewAuthUser()
	identifiers := map[string]interface{}{"username": "alice"}
	credentials := map[string]interface{}{"password": "secret"}
	meta := &authnprovidercm.AuthnMetadata{}

	s.mockProvider.On("Authenticate", context.Background(), identifiers, credentials, meta).
		Return(&authnprovidercm.AuthnResult{
			UserID:                    "user-1",
			UserType:                  "customer",
			OUID:                      "ou-1",
			Token:                     "tok",
			IsAttributeValuesIncluded: false,
			AttributesResponse:        nil,
		}, (*serviceerror.ServiceError)(nil))

	result, svcErr := s.mgr.AuthenticateUser(context.Background(), identifiers, credentials, nil, meta, authUser)

	s.Nil(svcErr)
	s.NotNil(result)
	s.Equal("user-1", result.UserID)
	s.Equal("ou-1", result.OUID)
	s.Equal("customer", result.UserType)

	s.Equal("user-1", authUser.userID)
	s.Equal("customer", authUser.userType)
	s.Equal("ou-1", authUser.ouID)

	pd, ok := authUser.getProviderData(defaultProvider)
	s.True(ok)
	s.Equal("tok", pd.token)
	s.False(pd.isAttributeValuesIncluded)
}

func (s *ManagerTestSuite) TestAuthenticateUser_ClientError() {
	authUser := NewAuthUser()
	identifiers := map[string]interface{}{"username": "alice"}
	credentials := map[string]interface{}{"password": "wrong"}
	meta := &authnprovidercm.AuthnMetadata{}
	provErr := &serviceerror.ServiceError{
		Code: "PROV-ERR", Type: serviceerror.ClientErrorType, Error: "invalid credentials",
	}

	s.mockProvider.On("Authenticate", context.Background(), identifiers, credentials, meta).
		Return((*authnprovidercm.AuthnResult)(nil), provErr)

	result, svcErr := s.mgr.AuthenticateUser(context.Background(), identifiers, credentials, nil, meta, authUser)

	s.NotNil(svcErr)
	s.Equal(ErrorAuthenticationFailed.Code, svcErr.Code)
	s.Equal(serviceerror.ClientErrorType, svcErr.Type)
	s.Nil(result)
	s.Empty(authUser.userID, "authUser must not be mutated on error")
}

func (s *ManagerTestSuite) TestAuthenticateUser_ServerError() {
	authUser := NewAuthUser()
	identifiers := map[string]interface{}{"username": "alice"}
	credentials := map[string]interface{}{"password": "secret"}
	meta := &authnprovidercm.AuthnMetadata{}
	provErr := &serviceerror.ServiceError{
		Code: "PROV-ERR", Type: serviceerror.ServerErrorType, Error: "database unavailable",
	}

	s.mockProvider.On("Authenticate", context.Background(), identifiers, credentials, meta).
		Return((*authnprovidercm.AuthnResult)(nil), provErr)

	result, svcErr := s.mgr.AuthenticateUser(context.Background(), identifiers, credentials, nil, meta, authUser)

	s.NotNil(svcErr)
	s.Equal(ErrorAuthServerError.Code, svcErr.Code)
	s.Equal(serviceerror.ServerErrorType, svcErr.Type)
	s.Nil(result)
	s.Empty(authUser.userID, "authUser must not be mutated on error")
}

func (s *ManagerTestSuite) TestAuthenticateUser_ReAuth() {
	authUser := NewAuthUser()
	identifiers := map[string]interface{}{"username": "alice"}
	credentials := map[string]interface{}{"password": "secret"}
	meta := &authnprovidercm.AuthnMetadata{}

	firstResult := &authnprovidercm.AuthnResult{
		UserID: "user-1", UserType: "customer", OUID: "ou-1", Token: "tok-first",
	}
	secondResult := &authnprovidercm.AuthnResult{
		UserID: "user-1", UserType: "customer", OUID: "ou-1", Token: "tok-second",
	}

	s.mockProvider.On("Authenticate", context.Background(), identifiers, credentials, meta).
		Return(firstResult, (*serviceerror.ServiceError)(nil)).Once()
	s.mockProvider.On("Authenticate", context.Background(), identifiers, credentials, meta).
		Return(secondResult, (*serviceerror.ServiceError)(nil)).Once()

	_, _ = s.mgr.AuthenticateUser(context.Background(), identifiers, credentials, nil, meta, authUser)
	_, _ = s.mgr.AuthenticateUser(context.Background(), identifiers, credentials, nil, meta, authUser)

	pd, ok := authUser.getProviderData(defaultProvider)
	s.True(ok)
	s.Equal("tok-second", pd.token, "second call must overwrite provider data")
}

func (s *ManagerTestSuite) TestGetUserAvailableAttributes_NilAuthUser() {
	attrs, svcErr := s.mgr.GetUserAvailableAttributes(context.Background(), nil)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorNotAuthenticated.Code, svcErr.Code)
}

func (s *ManagerTestSuite) TestGetUserAvailableAttributes_WithData() {
	authUser := NewAuthUser()
	expectedAttrs := &authnprovidercm.AttributesResponse{
		Attributes: map[string]*authnprovidercm.AttributeResponse{
			"email": {Value: "a@b.com"},
		},
	}
	authUser.setProviderData(defaultProvider, providerData{
		token:                     "tok",
		attributes:                expectedAttrs,
		isAttributeValuesIncluded: true,
	})

	attrs, svcErr := s.mgr.GetUserAvailableAttributes(context.Background(), authUser)
	s.Nil(svcErr)
	s.Equal(expectedAttrs, attrs)
	// No provider call should have been made
	s.mockProvider.AssertNotCalled(s.T(), "GetAttributes")
}

func (s *ManagerTestSuite) TestGetUserAttributes_NilAuthUser() {
	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), nil, nil)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorNotAuthenticated.Code, svcErr.Code)
}

func (s *ManagerTestSuite) TestGetUserAttributes_CacheHit() {
	authUser := NewAuthUser()
	expectedAttrs := &authnprovidercm.AttributesResponse{
		Attributes: map[string]*authnprovidercm.AttributeResponse{
			"email": {Value: "a@b.com"},
		},
	}
	authUser.setProviderData(defaultProvider, providerData{
		token:                     "tok",
		attributes:                expectedAttrs,
		isAttributeValuesIncluded: true,
	})

	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), nil, authUser)
	s.Nil(svcErr)
	s.Equal(expectedAttrs, attrs)
	s.mockProvider.AssertNotCalled(s.T(), "GetAttributes")
}

func (s *ManagerTestSuite) TestGetUserAvailableAttributes_NoProviderData() {
	authUser := NewAuthUser() // authenticated but no provider data set
	attrs, svcErr := s.mgr.GetUserAvailableAttributes(context.Background(), authUser)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorProviderDataNotFound.Code, svcErr.Code)
}

func (s *ManagerTestSuite) TestGetUserAttributes_NoProviderData() {
	authUser := NewAuthUser() // authenticated but no provider data set
	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), nil, authUser)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorProviderDataNotFound.Code, svcErr.Code)
}

func (s *ManagerTestSuite) TestGetUserAttributes_CacheMissServerError() {
	authUser := NewAuthUser()
	authUser.setProviderData(defaultProvider, providerData{token: "tok", isAttributeValuesIncluded: false})

	requestedAttrs := &authnprovidercm.RequestedAttributes{}
	provErr := &serviceerror.ServiceError{
		Code: "PROVIDER-ERR", Type: serviceerror.ServerErrorType, Error: "provider failure",
	}

	s.mockProvider.On("GetAttributes", context.Background(), "tok", requestedAttrs,
		(*authnprovidercm.GetAttributesMetadata)(nil)).
		Return((*authnprovidercm.GetAttributesResult)(nil), provErr)

	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), requestedAttrs, authUser)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorGetAttributesFailed.Code, svcErr.Code)
	s.Equal(serviceerror.ServerErrorType, svcErr.Type)
}

func (s *ManagerTestSuite) TestGetUserAttributes_CacheMissClientError() {
	authUser := NewAuthUser()
	authUser.setProviderData(defaultProvider, providerData{token: "expired-tok", isAttributeValuesIncluded: false})

	requestedAttrs := &authnprovidercm.RequestedAttributes{}
	provErr := &serviceerror.ServiceError{
		Code: "PROVIDER-ERR", Type: serviceerror.ClientErrorType, Error: "token expired",
	}

	s.mockProvider.On("GetAttributes", context.Background(), "expired-tok", requestedAttrs,
		(*authnprovidercm.GetAttributesMetadata)(nil)).
		Return((*authnprovidercm.GetAttributesResult)(nil), provErr)

	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), requestedAttrs, authUser)
	s.Nil(attrs)
	s.NotNil(svcErr)
	s.Equal(ErrorGetAttributesClientError.Code, svcErr.Code)
	s.Equal(serviceerror.ClientErrorType, svcErr.Type)
}

func (s *ManagerTestSuite) TestGetUserAttributes_CacheMiss() {
	authUser := NewAuthUser()
	authUser.setProviderData(defaultProvider, providerData{
		token:                     "tok",
		attributes:                nil,
		isAttributeValuesIncluded: false,
	})

	requestedAttrs := &authnprovidercm.RequestedAttributes{}
	fetchedAttrs := &authnprovidercm.AttributesResponse{
		Attributes: map[string]*authnprovidercm.AttributeResponse{
			"email": {Value: "fetched@b.com"},
		},
	}

	s.mockProvider.On("GetAttributes", context.Background(), "tok", requestedAttrs,
		(*authnprovidercm.GetAttributesMetadata)(nil)).
		Return(&authnprovidercm.GetAttributesResult{AttributesResponse: fetchedAttrs},
			(*serviceerror.ServiceError)(nil))

	attrs, svcErr := s.mgr.GetUserAttributes(context.Background(), requestedAttrs, authUser)
	s.Nil(svcErr)
	s.Equal(fetchedAttrs, attrs)

	// AuthUser must be updated with the fetched attributes
	pd, _ := authUser.getProviderData(defaultProvider)
	s.True(pd.isAttributeValuesIncluded)
	s.Equal(fetchedAttrs, pd.attributes)
}
