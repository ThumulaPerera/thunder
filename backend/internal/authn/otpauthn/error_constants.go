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

package otpauthn

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// Client errors for OTP authentication proxy service.
var (
	ErrorInvalidSenderID = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1001",
		Error:            "Invalid sender ID",
		ErrorDescription: "The provided sender ID is invalid or empty",
	}
	ErrorInvalidRecipient = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1002",
		Error:            "Invalid recipient",
		ErrorDescription: "The provided recipient is invalid or empty",
	}
	ErrorUnsupportedChannel = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1003",
		Error:            "Unsupported channel",
		ErrorDescription: "The provided channel is not supported",
	}
	ErrorSendOTPFailed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1004",
		Error:            "Failed to send OTP",
		ErrorDescription: "An error occurred while sending the OTP",
	}
	ErrorInvalidSessionToken = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1005",
		Error:            "Invalid session token",
		ErrorDescription: "The provided session token is invalid or expired",
	}
	ErrorInvalidOTP = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1006",
		Error:            "Invalid OTP",
		ErrorDescription: "The provided OTP is invalid or empty",
	}
	ErrorIncorrectOTP = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1007",
		Error:            "Incorrect OTP",
		ErrorDescription: "The provided OTP is incorrect or has expired",
	}
	ErrorVerifyOTPFailed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1008",
		Error:            "Failed to verify OTP",
		ErrorDescription: "An error occurred while verifying the OTP",
	}
	ErrorAuthenticationFailed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1009",
		Error:            "Authentication failed",
		ErrorDescription: "The authentication attempt failed",
	}
	ErrorInvalidRequest = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1010",
		Error:            "Invalid request",
		ErrorDescription: "The authentication request is invalid",
	}
	ErrorUserNotFound = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-OTPAUTHN-1011",
		Error:            "User not found",
		ErrorDescription: "No user found for the provided credentials",
	}
)
