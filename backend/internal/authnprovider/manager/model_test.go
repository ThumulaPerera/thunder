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
	"testing"

	"github.com/stretchr/testify/suite"
)

type ModelTestSuite struct {
	suite.Suite
}

func TestModelTestSuite(t *testing.T) {
	suite.Run(t, new(ModelTestSuite))
}

func (s *ModelTestSuite) TestAuthUserMarshalUnmarshal() {
	authUser := AuthUser{
		userID:   "user-123",
		userType: "customer",
		ouID:     "ou-456",
		authHistory: []*AuthResult{
			{
				token: "secret-token",
				providerAttributes: map[string]interface{}{
					"email": "test@example.com",
				},
				isProviderAttributeValuesIncluded: true,
			},
		},
	}

	// Marshal
	data, err := json.Marshal(&authUser)
	s.NoError(err)

	// Unmarshal into a new AuthUser
	var restored AuthUser
	err = json.Unmarshal(data, &restored)
	s.NoError(err)

	// Identity round-trips correctly
	s.Equal("user-123", restored.userID)
	s.Equal("customer", restored.userType)
	s.Equal("ou-456", restored.ouID)

	// Auth history round-trips correctly
	s.Require().Len(restored.authHistory, 1)
	ar := restored.authHistory[0]
	s.Equal("secret-token", ar.token)
	s.True(ar.isProviderAttributeValuesIncluded)
	s.NotNil(ar.providerAttributes)
	s.Equal("test@example.com", ar.providerAttributes["email"])
}

func (s *ModelTestSuite) TestAuthUserIsSet_ZeroValue() {
	var a AuthUser
	s.False(a.IsSet())
}

func (s *ModelTestSuite) TestAuthUserIsSet_EmptyAuthUser() {
	a := AuthUser{}
	s.False(a.IsSet())
}

func (s *ModelTestSuite) TestAuthUserIsSet_WithUserID() {
	a := AuthUser{}
	a.userID = "user-123"
	a.userType = "customer"
	a.ouID = "ou-456"
	s.True(a.IsSet())
}

func (s *ModelTestSuite) TestAuthUserIsSet_WithOnlyAuthHistory() {
	a := AuthUser{}
	a.authHistory = []*AuthResult{
		{token: "tok"},
	}
	s.True(a.IsSet())
}

func (s *ModelTestSuite) TestAuthUserMarshalNilAuthHistory() {
	// An empty AuthUser must marshal and unmarshal without panicking
	authUser := AuthUser{}

	data, err := json.Marshal(&authUser)
	s.NoError(err)
	s.NotEmpty(data)

	var restored AuthUser
	err = json.Unmarshal(data, &restored)
	s.NoError(err)
	s.Empty(restored.userID)
	s.Empty(restored.authHistory)
}
