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

package userprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type RestUserProviderTestSuite struct {
	suite.Suite
}

func TestRestUserProviderTestSuite(t *testing.T) {
	suite.Run(t, new(RestUserProviderTestSuite))
}

func (suite *RestUserProviderTestSuite) TestIdentifyUser() {
	// Success case
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/identify", r.URL.Path)
		suite.Equal(http.MethodPost, r.Method)
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(IdentifyUserResponse{UserID: "user123"})
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	userID, err := provider.IdentifyUser(map[string]interface{}{"email": "test@test.com"})

	suite.Nil(err)
	suite.Equal("user123", *userID)

	// Error case (Not Found)
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(UserProviderError{Code: ErrorCodeUserNotFound, Message: "Not Found"})
	}))
	defer tsErr.Close()

	providerErr := NewRestUserProvider(tsErr.URL, "test-api-key", time.Second)
	userID, err = providerErr.IdentifyUser(map[string]interface{}{})
	suite.Nil(userID)
	suite.NotNil(err)
	suite.Equal(ErrorCodeUserNotFound, err.Code)
}

func (suite *RestUserProviderTestSuite) TestGetUser() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/users/user123", r.URL.Path)
		suite.Equal(http.MethodGet, r.Method)
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{UserID: "user123", UserType: "customer"})
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	u, err := provider.GetUser("user123")
	suite.Nil(err)
	suite.Equal("user123", u.UserID)
	suite.Equal("customer", u.UserType)

	// Test Error Decoding
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(UserProviderError{Code: ErrorCodeSystemError})
	}))
	defer tsErr.Close()

	providerErr := NewRestUserProvider(tsErr.URL, "test-api-key", time.Second)
	u, err = providerErr.GetUser("user123")
	suite.Nil(u)
	suite.NotNil(err)
	suite.Equal(ErrorCodeSystemError, err.Code)
}

func (suite *RestUserProviderTestSuite) TestGetUserGroups() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/users/user123/groups", r.URL.Path)
		q := r.URL.Query()
		suite.Equal("10", q.Get("limit"))
		suite.Equal("5", q.Get("offset"))
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(UserGroupListResponse{
			Groups: []UserGroup{{ID: "g1"}},
		})
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	resp, err := provider.GetUserGroups("user123", 10, 5)
	suite.Nil(err)
	suite.Equal(1, len(resp.Groups))
	suite.Equal("g1", resp.Groups[0].ID)
}

func (suite *RestUserProviderTestSuite) TestUpdateUser() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/users/user123", r.URL.Path)
		suite.Equal(http.MethodPut, r.Method)
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		var u User
		_ = json.NewDecoder(r.Body).Decode(&u)
		suite.Equal("updated", u.UserType)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(u)
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	u, err := provider.UpdateUser("user123", &User{UserType: "updated"})
	suite.Nil(err)
	suite.Equal("updated", u.UserType)
}

func (suite *RestUserProviderTestSuite) TestCreateUser() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/users", r.URL.Path)
		suite.Equal(http.MethodPost, r.Method)
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(User{UserID: "created"})
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	u, err := provider.CreateUser(&User{UserType: "new"})
	suite.Nil(err)
	suite.Equal("created", u.UserID)
}

func (suite *RestUserProviderTestSuite) TestUpdateUserCredentials() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.Equal("/users/user123/credentials", r.URL.Path)
		suite.Equal(http.MethodPut, r.Method)
		suite.Equal("test-api-key", r.Header.Get("X-API-KEY"))

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	provider := NewRestUserProvider(ts.URL, "test-api-key", time.Second)
	err := provider.UpdateUserCredentials("user123", json.RawMessage(`{}`))
	suite.Nil(err)

	// Failure
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(UserProviderError{Code: ErrorCodeInvalidRequestFormat})
	}))
	defer tsErr.Close()

	providerErr := NewRestUserProvider(tsErr.URL, "test-api-key", time.Second)
	err = providerErr.UpdateUserCredentials("user123", json.RawMessage(`{}`))
	suite.NotNil(err)
	suite.Equal(ErrorCodeInvalidRequestFormat, err.Code)
}
