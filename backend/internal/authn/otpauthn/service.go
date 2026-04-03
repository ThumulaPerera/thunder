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

// Package otpauthn provides a proxy layer over the otp authentication service.
package otpauthn

import (
	"context"

	"github.com/asgardeo/thunder/internal/authn/otp"
	notifcommon "github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/userprovider"
)

// OTPAuthnInterface defines the interface for the OTP authentication proxy service.
type OTPAuthnInterface interface {
	SendOTP(ctx context.Context, senderID string, channel notifcommon.ChannelType,
		recipient string) (string, *serviceerror.ServiceError)
	VerifyOTP(ctx context.Context, sessionToken, otp string) *serviceerror.ServiceError
	Authenticate(ctx context.Context, sessionToken, otp string) (*userprovider.User, *serviceerror.ServiceError)
}

// otpAuthnService is the proxy implementation of OTPAuthnInterface.
type otpAuthnService struct {
	otpService otp.OTPAuthnServiceInterface
}

// newOTPAuthnService creates a new instance of otpAuthnService.
func newOTPAuthnService(otpSvc otp.OTPAuthnServiceInterface) OTPAuthnInterface {
	return &otpAuthnService{otpService: otpSvc}
}

// SendOTP delegates to the underlying otp service.
func (s *otpAuthnService) SendOTP(ctx context.Context, senderID string, channel notifcommon.ChannelType,
	recipient string) (string, *serviceerror.ServiceError) {
	return s.otpService.SendOTP(ctx, senderID, channel, recipient)
}

// VerifyOTP delegates to the underlying otp service.
func (s *otpAuthnService) VerifyOTP(ctx context.Context, sessionToken, otpCode string) *serviceerror.ServiceError {
	return s.otpService.VerifyOTP(ctx, sessionToken, otpCode)
}

// Authenticate delegates to the underlying otp service.
func (s *otpAuthnService) Authenticate(ctx context.Context, sessionToken,
	otpCode string) (*userprovider.User, *serviceerror.ServiceError) {
	return s.otpService.Authenticate(ctx, sessionToken, otpCode)
}
