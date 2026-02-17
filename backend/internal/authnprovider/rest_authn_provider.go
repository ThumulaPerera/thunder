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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// RestAuthnProvider is an authentication provider that communicates with an external service via REST.
type RestAuthnProvider struct {
	baseURL    string
	httpClient *http.Client
}

// AuthenticateRequest is the request body for the authentication endpoint.
type AuthenticateRequest struct {
	Identifiers map[string]interface{} `json:"identifiers"`
	Credentials map[string]interface{} `json:"credentials"`
	Metadata    *AuthnMetadata         `json:"metadata"`
}

// GetAttributesRequest is the request body for the attributes endpoint.
type GetAttributesRequest struct {
	Token               string                 `json:"token"`
	RequestedAttributes []string               `json:"requestedAttributes"`
	Metadata            *GetAttributesMetadata `json:"metadata"`
}

// NewRestAuthnProvider creates a new REST authentication provider.
func NewRestAuthnProvider(baseURL string, timeout time.Duration) *RestAuthnProvider {
	return &RestAuthnProvider{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Authenticate authenticates a user.
func (p *RestAuthnProvider) Authenticate(identifiers, credentials map[string]interface{},
	metadata *AuthnMetadata) (*AuthnResult, *AuthnProviderError) {
	reqBody := AuthenticateRequest{
		Identifiers: identifiers,
		Credentials: credentials,
		Metadata:    metadata,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "Failed to marshal request", err.Error())
	}

	resp, err := p.httpClient.Post(p.baseURL+"/authenticate", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "Failed to send request", err.Error())
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		var result AuthnResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, NewError(ErrorCodeSystemError, "Failed to decode response", err.Error())
		}
		return &result, nil
	}

	return nil, p.decodeError(resp.Body)
}

// GetAttributes retrieves the attributes of a user.
func (p *RestAuthnProvider) GetAttributes(token string, requestedAttributes []string,
	metadata *GetAttributesMetadata) (*GetAttributesResult, *AuthnProviderError) {
	reqBody := GetAttributesRequest{
		Token:               token,
		RequestedAttributes: requestedAttributes,
		Metadata:            metadata,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "Failed to marshal request", err.Error())
	}

	resp, err := p.httpClient.Post(p.baseURL+"/attributes", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, NewError(ErrorCodeSystemError, "Failed to send request", err.Error())
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		var result GetAttributesResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, NewError(ErrorCodeSystemError, "Failed to decode response", err.Error())
		}
		return &result, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *RestAuthnProvider) decodeError(body io.Reader) *AuthnProviderError {
	var authnError AuthnProviderError
	if err := json.NewDecoder(body).Decode(&authnError); err != nil {
		return NewError(ErrorCodeSystemError, "Failed to decode error response", err.Error())
	}
	return &authnError
}
