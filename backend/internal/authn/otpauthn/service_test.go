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

	"github.com/stretchr/testify/suite"

	notifcommon "github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/userprovider"
	"github.com/asgardeo/thunder/tests/mocks/authn/otpmock"
)

type OTPAuthnServiceTestSuite struct {
	suite.Suite
	mockOTPService *otpmock.OTPAuthnServiceInterfaceMock
	service        OTPAuthnInterface
}

func TestOTPAuthnServiceTestSuite(t *testing.T) {
	suite.Run(t, new(OTPAuthnServiceTestSuite))
}

func (suite *OTPAuthnServiceTestSuite) SetupTest() {
	suite.mockOTPService = otpmock.NewOTPAuthnServiceInterfaceMock(suite.T())
	suite.service = newOTPAuthnService(suite.mockOTPService)
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

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_DelegatesToUnderlyingService() {
	ctx := context.Background()
	expectedUser := &userprovider.User{
		UserID: "user-123",
	}

	suite.mockOTPService.On("Authenticate", ctx, "token123", "123456").
		Return(expectedUser, (*serviceerror.ServiceError)(nil))

	user, svcErr := suite.service.Authenticate(ctx, "token123", "123456")

	suite.Nil(svcErr)
	suite.Equal(expectedUser, user)
	suite.mockOTPService.AssertExpectations(suite.T())
}

func (suite *OTPAuthnServiceTestSuite) TestAuthenticate_ReturnsErrorFromUnderlyingService() {
	ctx := context.Background()
	expectedErr := &serviceerror.ServiceError{
		Type:  serviceerror.ClientErrorType,
		Code:  "AUTHN-OTP-1006",
		Error: "Incorrect OTP",
	}

	suite.mockOTPService.On("Authenticate", ctx, "token123", "wrong").
		Return((*userprovider.User)(nil), expectedErr)

	user, svcErr := suite.service.Authenticate(ctx, "token123", "wrong")

	suite.Equal(expectedErr, svcErr)
	suite.Nil(user)
	suite.mockOTPService.AssertExpectations(suite.T())
}
