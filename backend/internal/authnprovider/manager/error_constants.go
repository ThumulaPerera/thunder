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

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

var (
	// ErrorAuthenticationFailed is returned when the underlying provider rejects the authentication
	// attempt due to a client-side reason (e.g. invalid credentials).
	ErrorAuthenticationFailed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-MGR-1001",
		Error:            "Authentication failed",
		ErrorDescription: "The authentication attempt failed",
	}

	// ErrorAuthServerError is returned when the underlying provider fails to process the
	// authentication attempt due to a server-side error.
	ErrorAuthServerError = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-MGR-1002",
		Error:            "Authentication server error",
		ErrorDescription: "An internal error occurred while processing the authentication attempt",
	}

	// ErrorGetAttributesFailed is returned when the underlying provider cannot fulfill the
	// attribute fetch due to a server-side error.
	ErrorGetAttributesFailed = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-MGR-1003",
		Error:            "Failed to get attributes",
		ErrorDescription: "An error occurred while fetching user attributes from the provider",
	}

	// ErrorGetAttributesClientError is returned when the underlying provider rejects the
	// attribute fetch due to a client-side reason (e.g. invalid or expired token).
	ErrorGetAttributesClientError = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-MGR-1004",
		Error:            "Failed to get attributes",
		ErrorDescription: "The attribute fetch was rejected by the provider",
	}

	// ErrorNotAuthenticated is returned when an attribute operation is requested but no authenticated
	// user session exists (authUser is nil).
	ErrorNotAuthenticated = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-MGR-1005",
		Error:            "User not authenticated",
		ErrorDescription: "The operation requires an authenticated user session",
	}

	// ErrorProviderDataNotFound is returned when no provider data exists for the user, meaning
	// authentication has not been completed through the expected provider.
	ErrorProviderDataNotFound = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-MGR-1006",
		Error:            "Provider data not found",
		ErrorDescription: "No authentication data found for the provider",
	}
)
