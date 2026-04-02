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
	"github.com/asgardeo/thunder/internal/authn/passkey"
	"github.com/asgardeo/thunder/internal/authnprovider/provider"
	"github.com/asgardeo/thunder/internal/user"
)

// InitializeAuthnProviderManager initializes and returns an AuthnProviderManagerInterface.
func InitializeAuthnProviderManager(userSvc user.UserServiceInterface,
	passkeySvc passkey.PasskeyServiceInterface) AuthnProviderManagerInterface {
	p := provider.InitializeAuthnProvider(userSvc, passkeySvc)
	return newAuthnProviderManager(p)
}
