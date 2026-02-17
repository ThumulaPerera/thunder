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

package authnprovider

import (
	"time"

	"github.com/asgardeo/thunder/internal/user"
)

// InitializeDefaultAuthnProvider initializes the default authentication provider.
func InitializeDefaultAuthnProvider(userSvc user.UserServiceInterface) AuthnProviderInterface {
	return NewDefaultAuthnProvider(userSvc)
}

// InitializeRestAuthnProvider initializes the REST authentication provider.
func InitializeRestAuthnProvider(baseURL, apiKey string, timeout time.Duration) AuthnProviderInterface {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return NewRestAuthnProvider(baseURL, apiKey, timeout)
}
