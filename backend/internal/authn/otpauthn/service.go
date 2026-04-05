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

	"github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/authn/otp"
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	notifcommon "github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// OTPAuthnInterface defines the interface for the OTP authentication proxy service.
type OTPAuthnInterface interface {
	SendOTP(ctx context.Context, senderID string, channel notifcommon.ChannelType,
		recipient string) (string, *serviceerror.ServiceError)
	VerifyOTP(ctx context.Context, sessionToken, otp string) *serviceerror.ServiceError
	Authenticate(ctx context.Context, sessionToken, otp string) (*authnprovidercm.AuthnResult,
		*serviceerror.ServiceError)
}

// otpAuthnService is the proxy implementation of OTPAuthnInterface.
type otpAuthnService struct {
	otpService    otp.OTPAuthnServiceInterface
	authnProvider authnprovidermgr.AuthnProviderManagerInterface
	logger        *log.Logger
}

// newOTPAuthnService creates a new instance of otpAuthnService.
func newOTPAuthnService(
	otpSvc otp.OTPAuthnServiceInterface,
	authnProvider authnprovidermgr.AuthnProviderManagerInterface,
) OTPAuthnInterface {
	service := &otpAuthnService{
		otpService:    otpSvc,
		authnProvider: authnProvider,
		logger:        log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OTPAuthnService")),
	}
	common.RegisterAuthenticator(service.getMetadata())
	return service
}

// SendOTP delegates to the underlying otp service.
func (s *otpAuthnService) SendOTP(ctx context.Context, senderID string, channel notifcommon.ChannelType,
	recipient string) (string, *serviceerror.ServiceError) {
	sessionToken, err := s.otpService.SendOTP(ctx, senderID, channel, recipient)
	if err != nil {
		if err.Type == serviceerror.ClientErrorType {
			switch err.Code {
			case otp.ErrorInvalidSenderID.Code:
				return "", newClientError(ErrorInvalidSenderID.Code, err.Error, err.ErrorDescription)
			case otp.ErrorInvalidRecipient.Code:
				return "", newClientError(ErrorInvalidRecipient.Code, err.Error, err.ErrorDescription)
			case otp.ErrorUnsupportedChannel.Code:
				return "", newClientError(ErrorUnsupportedChannel.Code, err.Error, err.ErrorDescription)
			case otp.ErrorClientErrorFromOTPService.Code:
				return "", newClientError(ErrorSendOTPFailed.Code, err.Error, err.ErrorDescription)
			default:
				return "", newClientError(ErrorSendOTPFailed.Code, err.Error, err.ErrorDescription)
			}
		}
		return "", s.logAndReturnServerError("SendOTP failed with server error",
			log.String("channel", string(channel)))
	}
	return sessionToken, nil
}

// VerifyOTP delegates to the underlying otp service.
func (s *otpAuthnService) VerifyOTP(ctx context.Context, sessionToken, otpCode string) *serviceerror.ServiceError {
	err := s.otpService.VerifyOTP(ctx, sessionToken, otpCode)
	if err != nil {
		if err.Type == serviceerror.ClientErrorType {
			switch err.Code {
			case otp.ErrorInvalidSessionToken.Code:
				return newClientError(ErrorInvalidSessionToken.Code, err.Error, err.ErrorDescription)
			case otp.ErrorInvalidOTP.Code:
				return newClientError(ErrorInvalidOTP.Code, err.Error, err.ErrorDescription)
			case otp.ErrorIncorrectOTP.Code:
				return newClientError(ErrorIncorrectOTP.Code, err.Error, err.ErrorDescription)
			case otp.ErrorClientErrorFromOTPService.Code:
				return newClientError(ErrorVerifyOTPFailed.Code, err.Error, err.ErrorDescription)
			default:
				return newClientError(ErrorVerifyOTPFailed.Code, err.Error, err.ErrorDescription)
			}
		}
		return s.logAndReturnServerError("VerifyOTP failed with server error")
	}
	return nil
}

// Authenticate delegates to the underlying otp service.
func (s *otpAuthnService) Authenticate(ctx context.Context, sessionToken,
	otpCode string) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	credentials := map[string]interface{}{
		"otp": map[string]interface{}{
			"sessionToken": sessionToken,
			"otp":          otpCode,
		},
	}
	authnResult, err := s.authnProvider.Authenticate(ctx, nil, credentials, nil)
	if err != nil {
		if err.Type == serviceerror.ClientErrorType {
			switch err.Code {
			case authnprovidercm.ErrorCodeAuthenticationFailed:
				return nil, newClientError(ErrorAuthenticationFailed.Code, err.Error, err.ErrorDescription)
			case authnprovidercm.ErrorCodeInvalidRequest:
				return nil, newClientError(ErrorInvalidRequest.Code, err.Error, err.ErrorDescription)
			case authnprovidercm.ErrorCodeUserNotFound:
				return nil, newClientError(ErrorUserNotFound.Code, err.Error, err.ErrorDescription)
			default:
				return nil, newClientError(ErrorAuthenticationFailed.Code, err.Error, err.ErrorDescription)
			}
		}
		return nil, s.logAndReturnServerError("Authenticate failed with server error")
	}
	return authnResult, nil
}

// getMetadata returns the authenticator metadata for OTP authenticator.
func (s *otpAuthnService) getMetadata() common.AuthenticatorMeta {
	return common.AuthenticatorMeta{
		Name:    common.AuthenticatorSMSOTP,
		Factors: []common.AuthenticationFactor{common.FactorPossession},
	}
}

// newClientError creates a new client ServiceError with the given code, message, and description.
func newClientError(code, msg, desc string) *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             code,
		Error:            msg,
		ErrorDescription: desc,
	}
}

// logAndReturnServerError logs the error and returns a generic server error.
func (s *otpAuthnService) logAndReturnServerError(msg string, fields ...log.Field) *serviceerror.ServiceError {
	s.logger.Error(msg, fields...)
	return &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-OTPAUTHN-0001",
		Error:            "System error",
		ErrorDescription: "An internal server error occurred",
	}
}
