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

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
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
	expectedErr := &serviceerror.ServiceError{
		Type:  serviceerror.ClientErrorType,
		Code:  "AUTHN-OTP-1001",
		Error: "Invalid sender ID",
	}

	suite.mockOTPService.On("SendOTP", ctx, "", notifcommon.ChannelTypeSMS, "recipient1").
		Return("", expectedErr)

	token, svcErr := suite.service.SendOTP(ctx, "", notifcommon.ChannelTypeSMS, "recipient1")

	suite.Equal(expectedErr, svcErr)
	suite.Empty(token)
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
	expectedErr := &serviceerror.ServiceError{
		Type:  serviceerror.ClientErrorType,
		Code:  "AUTHN-OTP-1006",
		Error: "Incorrect OTP",
	}

	suite.mockOTPService.On("VerifyOTP", ctx, "token123", "wrong").
		Return(expectedErr)

	svcErr := suite.service.VerifyOTP(ctx, "token123", "wrong")

	suite.Equal(expectedErr, svcErr)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_DelegatesToAuthnProvider() {
	ctx := context.Background()
	expectedResult := &authnprovidercm.AuthnResult{
		UserID:   "user-123",
		UserType: "person",
		OUID:     "ou-123",
	}

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return(expectedResult, (*authnprovidercm.AuthnProviderError)(nil))

	result, svcErr := suite.service.Authenticate(ctx, "token123", "123456")

	suite.Nil(svcErr)
	suite.Equal(expectedResult, result)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_ReturnsErrorFromAuthnProvider() {
	ctx := context.Background()
	providerErr := authnprovidercm.NewError(
		authnprovidercm.ErrorCodeAuthenticationFailed,
		"Incorrect OTP",
		"The provided OTP is incorrect",
	)

	suite.mockAuthnProvider.On("Authenticate", ctx, mock.Anything, mock.Anything, mock.Anything).
		Return((*authnprovidercm.AuthnResult)(nil), providerErr)

	result, svcErr := suite.service.Authenticate(ctx, "token123", "wrong")

	suite.NotNil(svcErr)
	suite.Nil(result)
	suite.Equal(string(authnprovidercm.ErrorCodeAuthenticationFailed), svcErr.Code)
	suite.mockAuthnProvider.AssertExpectations(suite.T())
}
