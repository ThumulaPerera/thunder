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

package otpauthn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/authn/otp"
	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	notifcommon "github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/tests/mocks/authn/otpmock"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/managermock"
)

type OTPAuthnServiceTestSuite struct {
	suite.Suite
	mockOTPService    *otpmock.OTPAuthnServiceInterfaceMock
	mockAuthnProvider *managermock.AuthnProviderManagerInterfaceMock
	service           OTPAuthnInterface
}

func TestOTPAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(OTPAuthnServiceTestSuite))
}

func (suite *OTPAuthnServiceTestSuite) SetupTest() {
	suite.mockOTPService = otpmock.NewOTPAuthnServiceInterfaceMock(suite.T())
	suite.mockAuthnProvider = managermock.NewAuthnProviderManagerInterfaceMock(suite.T())
	suite.service = newOTPAuthnService(suite.mockOTPService, suite.mockAuthnProvider)
}

func (suite *OTPAuthnServiceTestSuite) TestRegistersAuthenticatorOnInit() {
	factors := common.GetAuthenticatorFactors(common.AuthenticatorSMSOTP)
	suite.Contains(factors, common.FactorPossession)
}

func (suite *OTPAuthnServiceTestSuite) TestSendOTP_DelegatesToUnderlyingService() {
	ctx := context.Background()
	expectedToken := "session-token-123"

	suite.mockOTPService.On("SendOTP", ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1").
		Return(expectedToken, (*serviceerror.ServiceError)(nil))

	token, svcErr := suite.service.SendOTP(ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1")

	suite.Nil(svcErr)
	suite.Equal(expectedToken, token)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestSendOTP_ReturnsErrorFromUnderlyingService() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             otp.ErrorInvalidSenderID.Code,
		Error:            "Invalid sender ID",
		ErrorDescription: "The provided sender ID is invalid or empty",
	}

	suite.mockOTPService.On("SendOTP", ctx, "", notifcommon.ChannelTypeSMS, "recipient1").
		Return("", mockErr)

	token, svcErr := suite.service.SendOTP(ctx, "", notifcommon.ChannelTypeSMS, "recipient1")

	suite.Empty(token)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorInvalidSenderID.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestSendOTP_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockOTPService.On("SendOTP", ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1").
		Return("", mockErr)

	token, svcErr := suite.service.SendOTP(ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1")

	suite.Empty(token)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorSendOTPFailed.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestSendOTP_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-OTP-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockOTPService.On("SendOTP", ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1").
		Return("", mockErr)

	token, svcErr := suite.service.SendOTP(ctx, "sender1", notifcommon.ChannelTypeSMS, "recipient1")

	suite.Empty(token)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-OTPAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestVerifyOTP_DelegatesToUnderlyingService() {
	ctx := context.Background()

	suite.mockOTPService.On("VerifyOTP", ctx, "token123", "123456").
		Return((*serviceerror.ServiceError)(nil))

	svcErr := suite.service.VerifyOTP(ctx, "token123", "123456")

	suite.Nil(svcErr)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestVerifyOTP_ReturnsErrorFromUnderlyingService() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             otp.ErrorIncorrectOTP.Code,
		Error:            "Incorrect OTP",
		ErrorDescription: "The provided OTP is incorrect or has expired",
	}

	suite.mockOTPService.On("VerifyOTP", ctx, "token123", "wrong").
		Return(mockErr)

	svcErr := suite.service.VerifyOTP(ctx, "token123", "wrong")

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorIncorrectOTP.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestVerifyOTP_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockOTPService.On("VerifyOTP", ctx, "token123", "wrong").
		Return(mockErr)

	svcErr := suite.service.VerifyOTP(ctx, "token123", "wrong")

	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorVerifyOTPFailed.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestVerifyOTP_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-OTP-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockOTPService.On("VerifyOTP", ctx, "token123", "wrong").
		Return(mockErr)

	svcErr := suite.service.VerifyOTP(ctx, "token123", "wrong")

	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-OTPAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_DelegatesToAuthnProvider() {
	ctx := context.Background()
	expectedResult := &authnprovidermgr.AuthnBasicResult{
		UserID:   "user-123",
		UserType: "person",
		OUID:     "ou-123",
	}

	suite.mockAuthnProvider.On("AuthenticateUser", ctx, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, expectedResult, (*serviceerror.ServiceError)(nil))

	_, result, svcErr := suite.service.Authenticate(ctx, "token123", "123456", authnprovidermgr.AuthUser{})

	suite.Nil(svcErr)
	suite.Equal(expectedResult, result)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_ReturnsErrorFromAuthnProvider() {
	ctx := context.Background()
	providerErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             authnprovidermgr.ErrorAuthenticationFailed.Code,
		Error:            "Incorrect OTP",
		ErrorDescription: "The provided OTP is incorrect",
	}

	suite.mockAuthnProvider.On("AuthenticateUser", ctx, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil), providerErr)

	_, result, svcErr := suite.service.Authenticate(ctx, "token123", "wrong", authnprovidermgr.AuthUser{})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorAuthenticationFailed.Code, svcErr.Code)
	suite.Equal(providerErr.Error, svcErr.Error)
	suite.Equal(providerErr.ErrorDescription, svcErr.ErrorDescription)
	suite.Equal(serviceerror.ClientErrorType, svcErr.Type)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_DefaultClientError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "UNKNOWN-CODE",
		Error:            "some error",
		ErrorDescription: "some description",
	}

	suite.mockAuthnProvider.On("AuthenticateUser", ctx, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil), mockErr)

	_, result, svcErr := suite.service.Authenticate(ctx, "token123", "wrong", authnprovidermgr.AuthUser{})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(ErrorAuthenticationFailed.Code, svcErr.Code)
	suite.Equal(mockErr.Error, svcErr.Error)
	suite.Equal(mockErr.ErrorDescription, svcErr.ErrorDescription)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_ServerError() {
	ctx := context.Background()
	mockErr := &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-OTP-9999",
		Error:            "internal error",
		ErrorDescription: "something broke",
	}

	suite.mockAuthnProvider.On("AuthenticateUser", ctx, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, (*authnprovidermgr.AuthnBasicResult)(nil), mockErr)

	_, result, svcErr := suite.service.Authenticate(ctx, "token123", "wrong", authnprovidermgr.AuthUser{})

	suite.Nil(result)
	suite.Require().NotNil(svcErr)
	suite.Equal(serviceerror.ServerErrorType, svcErr.Type)
	suite.Equal("AUTHN-OTPAUTHN-0001", svcErr.Code)
	suite.Equal("System error", svcErr.Error)
	suite.Equal("An internal server error occurred", svcErr.ErrorDescription)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}
