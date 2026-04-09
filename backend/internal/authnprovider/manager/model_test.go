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
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	"github.com/asgardeo/thunder/internal/system/config"
)

type ModelTestSuite struct {
	suite.Suite
}

func TestModelTestSuite(t *testing.T) {
	testConfig := &config.Config{
		Crypto: config.CryptoConfig{
			Encryption: config.EncryptionConfig{
				Key: "2729a7928c79371e5f312167269294a14bb0660fd166b02a408a20fa73271580",
			},
		},
	}
	config.ResetThunderRuntime()
	err := config.InitializeThunderRuntime("/test/thunder/home", testConfig)
	if err != nil {
		t.Fatalf("Failed to initialize Thunder runtime: %v", err)
	}
	suite.Run(t, new(ModelTestSuite))
}

func (s *ModelTestSuite) TestAuthUserMarshalUnmarshal() {
	var authUser AuthUser
	authUser.setIdentity("user-123", "customer", "ou-456")
	authUser.setProviderData(defaultProvider, providerData{
		token: "secret-token",
		attributes: &authnprovidercm.AttributesResponse{
			Attributes: map[string]*authnprovidercm.AttributeResponse{
				"email": {Value: "test@example.com"},
			},
		},
		isAttributeValuesIncluded: true,
	})

	// Marshal
	data, err := json.Marshal(&authUser)
	s.NoError(err)

	// Token must not appear in plaintext
	s.False(strings.Contains(string(data), "secret-token"), "token must be encrypted in JSON")

	// Unmarshal into a new AuthUser
	var restored AuthUser
	err = json.Unmarshal(data, &restored)
	s.NoError(err)

	// Identity round-trips correctly
	s.Equal("user-123", restored.userID)
	s.Equal("customer", restored.userType)
	s.Equal("ou-456", restored.ouID)

	// Provider data round-trips correctly
	pd, ok := restored.getProviderData(defaultProvider)
	s.True(ok)
	s.Equal("secret-token", pd.token)
	s.True(pd.isAttributeValuesIncluded)
	s.NotNil(pd.attributes)
	s.Equal("test@example.com", pd.attributes.Attributes["email"].Value)
}

func (s *ModelTestSuite) TestAuthUserIsAuthenticated_ZeroValue() {
	var a AuthUser
	s.False(a.IsAuthenticated())
}

func (s *ModelTestSuite) TestAuthUserIsAuthenticated_EmptyAuthUser() {
	a := AuthUser{}
	s.False(a.IsAuthenticated())
}

func (s *ModelTestSuite) TestAuthUserIsAuthenticated_WithUserID() {
	a := AuthUser{}
	a.setIdentity("user-123", "customer", "ou-456")
	s.True(a.IsAuthenticated())
}

func (s *ModelTestSuite) TestAuthUserMarshalNilProviderData() {
	// An empty AuthUser must marshal and unmarshal without panicking
	authUser := AuthUser{}

	data, err := json.Marshal(&authUser)
	s.NoError(err)
	s.NotEmpty(data)

	var restored AuthUser
	err = json.Unmarshal(data, &restored)
	s.NoError(err)
	s.Empty(restored.userID)
	s.Empty(restored.providersAuthData)
}
