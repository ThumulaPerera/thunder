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
	"encoding/json"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
)

// ProviderUserState represents the local user resolution state from the authn provider.
type ProviderUserState string

// ProviderUserState values representing local user resolution outcomes.
const (
	ProviderUserStateExists    ProviderUserState = "exists"
	ProviderUserStateNotExists ProviderUserState = "not_exists"
	ProviderUserStateAmbiguous ProviderUserState = "ambiguous"
)

// AuthUser accumulates per-provider authentication state produced during flow execution.
// All fields are unexported; use the manager methods to interact with this type.
type AuthUser struct {
	userID      string
	userType    string
	ouID        string
	authHistory []*AuthResult
}

// AuthResult holds the outcome of a single authentication step.
type AuthResult struct {
	authType                          string
	isVerified                        bool
	token                             string
	providerAttributes                map[string]interface{}
	isProviderAttributeValuesIncluded bool
	localUserState                    ProviderUserState
	runtimeAttributes                 map[string]interface{}
}

// IsSet reports whether this AuthUser has been populated (i.e. is not the zero value).
func (a AuthUser) IsSet() bool {
	return a.userID != "" || a.userType != "" || a.ouID != "" || len(a.authHistory) > 0
}

// GetUserID returns the user ID of the authenticated user, or an empty string if not set.
func (a AuthUser) GetUserID() string {
	return a.userID
}

// GetOUID returns the organizational unit ID of the authenticated user, or an empty string if not set.
func (a AuthUser) GetOUID() string {
	return a.ouID
}

// GetUserType returns the user type of the authenticated user, or an empty string if not set.
func (a AuthUser) GetUserType() string {
	return a.userType
}

// IsLocalUserExists returns true if all authentication steps indicate that a local user exists for
// the authenticated identity.
func (a AuthUser) IsLocalUserExists() bool {
	for _, authResult := range a.authHistory {
		if authResult.localUserState != ProviderUserStateExists {
			return false
		}
	}
	return true
}

// IsLocalUserAmbiguous returns true if any authentication step indicates that the authenticated identity
// is ambiguously mapped to multiple local users.
func (a AuthUser) IsLocalUserAmbiguous() bool {
	for _, authResult := range a.authHistory {
		if authResult.localUserState == ProviderUserStateAmbiguous {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true if all authentication steps are verified and at least one step exists.
func (a AuthUser) IsAuthenticated() bool {
	for _, authResult := range a.authHistory {
		if !authResult.isVerified || authResult.localUserState != ProviderUserStateExists {
			return false
		}
	}
	return len(a.authHistory) > 0
}

// GetLastFederatedSub returns the subject claim from the most recent federated auth result.
func (a *AuthUser) GetLastFederatedSub() string {
	sub, ok := a.GetRuntimeAttribute("sub").(string)
	if ok {
		return sub
	}
	return ""
}

// GetRuntimeAttribute returns the runtime attribute value for the given key from the last auth result.
func (a *AuthUser) GetRuntimeAttribute(key string) interface{} {
	runtimeAttributes := a.GetRuntimeAttributes()
	if runtimeAttributes == nil {
		return nil
	}
	return runtimeAttributes[key]
}

// GetRuntimeAttributes returns all runtime attributes from the last auth result.
func (a *AuthUser) GetRuntimeAttributes() map[string]interface{} {
	if len(a.authHistory) == 0 {
		return nil
	}
	lastAuthResult := a.authHistory[len(a.authHistory)-1]
	return lastAuthResult.runtimeAttributes
}

func (a *AuthUser) getLastAuthResult() *AuthResult {
	if len(a.authHistory) == 0 {
		return nil
	}
	return a.authHistory[len(a.authHistory)-1]
}

// authUserJSON is the internal proxy used for JSON serialization of AuthUser.
type authUserJSON struct {
	UserID      string           `json:"userId"`
	UserType    string           `json:"userType"`
	OUID        string           `json:"ouId"`
	AuthHistory []authResultJSON `json:"authHistory"`
}

// authResultJSON is the internal proxy used for JSON serialization of AuthResult.
type authResultJSON struct {
	AuthType                          string                              `json:"authType"`
	IsVerified                        bool                                `json:"isVerified"`
	Token                             string                              `json:"token"`
	Attributes                        *authnprovidercm.AttributesResponse `json:"attributes,omitempty"`
	ProviderAttributes                map[string]interface{}              `json:"providerAttributes,omitempty"`
	IsProviderAttributeValuesIncluded bool                                `json:"isProviderAttributeValuesIncluded"`
	LocalUserState                    string                              `json:"localUserState"`
	RuntimeAttributes                 map[string]interface{}              `json:"runtimeAttributes,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (a *AuthUser) MarshalJSON() ([]byte, error) {
	proxy := authUserJSON{
		UserID:      a.userID,
		UserType:    a.userType,
		OUID:        a.ouID,
		AuthHistory: make([]authResultJSON, len(a.authHistory)),
	}

	for i, r := range a.authHistory {
		proxy.AuthHistory[i] = authResultJSON{
			AuthType:                          r.authType,
			IsVerified:                        r.isVerified,
			Token:                             r.token,
			ProviderAttributes:                r.providerAttributes,
			IsProviderAttributeValuesIncluded: r.isProviderAttributeValuesIncluded,
			LocalUserState:                    string(r.localUserState),
			RuntimeAttributes:                 r.runtimeAttributes,
		}
	}

	return json.Marshal(proxy)
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *AuthUser) UnmarshalJSON(b []byte) error {
	var proxy authUserJSON
	if err := json.Unmarshal(b, &proxy); err != nil {
		return err
	}

	a.userID = proxy.UserID
	a.userType = proxy.UserType
	a.ouID = proxy.OUID
	a.authHistory = make([]*AuthResult, len(proxy.AuthHistory))

	for i, r := range proxy.AuthHistory {
		a.authHistory[i] = &AuthResult{
			authType:                          r.AuthType,
			isVerified:                        r.IsVerified,
			token:                             r.Token,
			providerAttributes:                r.ProviderAttributes,
			isProviderAttributeValuesIncluded: r.IsProviderAttributeValuesIncluded,
			localUserState:                    ProviderUserState(r.LocalUserState),
			runtimeAttributes:                 r.RuntimeAttributes,
		}
	}

	return nil
}
