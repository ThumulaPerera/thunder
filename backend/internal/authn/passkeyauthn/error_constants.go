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

package passkeyauthn

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// Client errors for passkey authentication proxy service.
var (
	ErrorInvalidFinishData = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1001",
		Error:            "Invalid request data",
		ErrorDescription: "The request data is null or missing required fields",
	}
	ErrorEmptyUserIdentifier = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1002",
		Error:            "Empty user identifier",
		ErrorDescription: "Either user ID or username must be provided",
	}
	ErrorEmptyRelyingPartyID = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1003",
		Error:            "Empty relying party ID",
		ErrorDescription: "The relying party ID is required",
	}
	ErrorUserNotFound = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1004",
		Error:            "User not found",
		ErrorDescription: "The specified user was not found",
	}
	ErrorEmptySessionToken = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1005",
		Error:            "Empty session token",
		ErrorDescription: "The session token is required",
	}
	ErrorInvalidAttestationResponse = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1006",
		Error:            "Invalid attestation response",
		ErrorDescription: "The attestation response is missing required fields",
	}
	ErrorInvalidSessionToken = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1007",
		Error:            "Invalid session token",
		ErrorDescription: "The session token is invalid or malformed",
	}
	ErrorSessionExpired = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1008",
		Error:            "Session expired",
		ErrorDescription: "The session has expired. Please start a new session",
	}
	ErrorNoCredentialsFound = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1009",
		Error:            "No credentials found",
		ErrorDescription: "No passkey credentials found for the user",
	}
	ErrorAuthenticationFailed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1010",
		Error:            "Authentication failed",
		ErrorDescription: "The passkey authentication attempt failed",
	}
	ErrorInvalidRequest = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-PSKAUTHN-1011",
		Error:            "Invalid request",
		ErrorDescription: "The authentication request is invalid",
	}
)
