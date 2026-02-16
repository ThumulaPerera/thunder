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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type RestUserProvider struct {
	baseURL    string
	httpClient *http.Client
}

type IdentifyUserRequest struct {
	Filters map[string]interface{} `json:"filters"`
}

type IdentifyUserResponse struct {
	UserID string `json:"userID"`
}

func NewRestUserProvider(baseURL string, timeout time.Duration) *RestUserProvider {
	return &RestUserProvider{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (p *RestUserProvider) IdentifyUser(filters map[string]interface{}) (*string, *UserProviderError) {
	reqBody := IdentifyUserRequest{
		Filters: filters,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, p.createSystemError("Failed to marshal request", err)
	}

	resp, err := p.httpClient.Post(p.baseURL+"/identify", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result IdentifyUserResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, p.createSystemError("Failed to decode response", err)
		}
		return &result.UserID, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestUserProvider) GetUser(userID string) (*User, *UserProviderError) {
	resp, err := p.httpClient.Get(fmt.Sprintf("%s/users/%s", p.baseURL, userID))
	if err != nil {
		return nil, p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var user User
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return nil, p.createSystemError("Failed to decode response", err)
		}
		return &user, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestUserProvider) GetUserGroups(userID string, limit, offset int) (*UserGroupListResponse, *UserProviderError) {
	u, err := url.Parse(fmt.Sprintf("%s/users/%s/groups", p.baseURL, userID))
	if err != nil {
		return nil, p.createSystemError("Invalid URL", err)
	}

	q := u.Query()
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("offset", fmt.Sprintf("%d", offset))
	u.RawQuery = q.Encode()

	resp, err := p.httpClient.Get(u.String())
	if err != nil {
		return nil, p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result UserGroupListResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, p.createSystemError("Failed to decode response", err)
		}
		return &result, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestUserProvider) UpdateUser(userID string, user *User) (*User, *UserProviderError) {
	jsonBody, err := json.Marshal(user)
	if err != nil {
		return nil, p.createSystemError("Failed to marshal request", err)
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/users/%s", p.baseURL, userID), bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, p.createSystemError("Failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var updatedUser User
		if err := json.NewDecoder(resp.Body).Decode(&updatedUser); err != nil {
			return nil, p.createSystemError("Failed to decode response", err)
		}
		return &updatedUser, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestUserProvider) CreateUser(user *User) (*User, *UserProviderError) {
	jsonBody, err := json.Marshal(user)
	if err != nil {
		return nil, p.createSystemError("Failed to marshal request", err)
	}

	resp, err := p.httpClient.Post(p.baseURL+"/users", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var createdUser User
		if err := json.NewDecoder(resp.Body).Decode(&createdUser); err != nil {
			return nil, p.createSystemError("Failed to decode response", err)
		}
		return &createdUser, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestUserProvider) UpdateUserCredentials(userID string, credentials json.RawMessage) *UserProviderError {
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/users/%s/credentials", p.baseURL, userID), bytes.NewBuffer(credentials))
	if err != nil {
		return p.createSystemError("Failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return p.createSystemError("Failed to send request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return p.decodeError(resp.Body)
}

func (p *RestUserProvider) createSystemError(msg string, err error) *UserProviderError {
	return NewUserProviderError(ErrorCodeSystemError, msg, err.Error())
}

func (p *RestUserProvider) decodeError(body io.Reader) *UserProviderError {
	var userProviderError UserProviderError
	if err := json.NewDecoder(body).Decode(&userProviderError); err != nil {
		return p.createSystemError("Failed to decode error response", err)
	}
	return &userProviderError
}
