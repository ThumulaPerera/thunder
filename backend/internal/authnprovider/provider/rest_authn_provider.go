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

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	systemhttp "github.com/asgardeo/thunder/internal/system/http"
)

// restAuthnProvider is an authentication provider that communicates with an external service via REST.
type restAuthnProvider struct {
	baseURL    string
	apiKey     string
	httpClient systemhttp.HTTPClientInterface
}

// AuthenticateRequest is the request body for the authentication endpoint.
type AuthenticateRequest struct {
	Identifiers map[string]interface{}         `json:"identifiers"`
	Credentials map[string]interface{}         `json:"credentials"`
	Metadata    *authnprovidercm.AuthnMetadata `json:"metadata"`
}

// GetAttributesRequest is the request body for the attributes endpoint.
type GetAttributesRequest struct {
	Token               string                                 `json:"token"`
	RequestedAttributes *authnprovidercm.RequestedAttributes   `json:"requestedAttributes"`
	Metadata            *authnprovidercm.GetAttributesMetadata `json:"metadata"`
}

// newRestAuthnProvider creates a new REST authentication provider.
func newRestAuthnProvider(baseURL, apiKey string, httpClient systemhttp.HTTPClientInterface) AuthnProviderInterface {
	return &restAuthnProvider{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

// Authenticate authenticates a user.
func (p *restAuthnProvider) Authenticate(ctx context.Context, identifiers, credentials map[string]interface{},
	metadata *authnprovidercm.AuthnMetadata) (*authnprovidercm.AuthnResult, *authnprovidercm.AuthnProviderError) {
	reqBody := AuthenticateRequest{
		Identifiers: identifiers,
		Credentials: credentials,
		Metadata:    metadata,
	}
	return postAndDecode[authnprovidercm.AuthnResult](p, ctx, p.baseURL+"/authenticate", reqBody)
}

// GetAttributes retrieves the attributes of a user.
func (p *restAuthnProvider) GetAttributes(ctx context.Context, token string,
	requestedAttributes *authnprovidercm.RequestedAttributes,
	metadata *authnprovidercm.GetAttributesMetadata) (
	*authnprovidercm.GetAttributesResult, *authnprovidercm.AuthnProviderError) {
	reqBody := GetAttributesRequest{
		Token:               token,
		RequestedAttributes: requestedAttributes,
		Metadata:            metadata,
	}
	return postAndDecode[authnprovidercm.GetAttributesResult](p, ctx, p.baseURL+"/attributes", reqBody)
}

// postAndDecode marshals reqBody as JSON, posts it to url, and decodes the response into T.
func postAndDecode[T any](p *restAuthnProvider, ctx context.Context, url string,
	reqBody interface{}) (*T, *authnprovidercm.AuthnProviderError) {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, "Failed to marshal request", err.Error())
	}

	resp, err := p.doRequest(ctx, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, "Failed to send request", err.Error())
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		var result T
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, authnprovidercm.NewError(
				authnprovidercm.ErrorCodeSystemError, "Failed to decode response", err.Error())
		}
		return &result, nil
	}

	return nil, p.decodeError(resp.Body)
}

func (p *restAuthnProvider) decodeError(body io.Reader) *authnprovidercm.AuthnProviderError {
	var authnError authnprovidercm.AuthnProviderError
	if err := json.NewDecoder(body).Decode(&authnError); err != nil {
		return authnprovidercm.NewError(
			authnprovidercm.ErrorCodeSystemError, "Failed to decode error response", err.Error())
	}
	return &authnError
}

func (p *restAuthnProvider) doRequest(ctx context.Context, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("API-KEY", p.apiKey)
	}
	return p.httpClient.Do(req)
}
