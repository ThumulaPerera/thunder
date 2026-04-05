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
	"context"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/authnprovider/provider"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
)

// authnProviderManager is a proxy struct that implements AuthnProviderManagerInterface by delegating
// to an underlying AuthnProviderInterface.
type authnProviderManager struct {
	provider provider.AuthnProviderInterface
}

// newAuthnProviderManager creates a new authnProviderManager.
func newAuthnProviderManager(p provider.AuthnProviderInterface) AuthnProviderManagerInterface {
	return &authnProviderManager{provider: p}
}

// Authenticate delegates to the underlying provider.
func (m *authnProviderManager) Authenticate(ctx context.Context, identifiers, credentials map[string]interface{},
	metadata *authnprovidercm.AuthnMetadata) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	return m.provider.Authenticate(ctx, identifiers, credentials, metadata)
}

// GetAttributes delegates to the underlying provider.
func (m *authnProviderManager) GetAttributes(ctx context.Context, token string,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata) (
	*authnprovidercm.GetAttributesResult, *serviceerror.ServiceError) {
	return m.provider.GetAttributes(ctx, token, requestedAttributes, metadata)
}
