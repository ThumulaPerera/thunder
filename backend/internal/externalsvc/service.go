/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package externalsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

const (
	// DefaultBaseURL is the default base URL for the external user service.
	DefaultBaseURL = "http://localhost:8091"

	// HTTP timeout for external service calls.
	httpTimeout = 30 * time.Second

	loggerComponentName = "ExternalService"
)

// externalService is an HTTP client implementation of ExternalSvcInterface.
type externalService struct {
	baseURL    string
	httpClient *http.Client
	logger     *log.Logger
}

// NewExternalService creates a new instance of ExternalSvcInterface.
func NewExternalService() ExternalSvcInterface {
	return &externalService{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		logger: log.GetLogger().With(log.String(log.LoggerKeyComponentName, loggerComponentName)),
	}
}

// identifyRequest represents the request body for identify user API.
type identifyRequest struct {
	Attributes map[string]interface{} `json:"attributes"`
}

// authenticateRequest represents the request body for authenticate user API.
type authenticateRequest struct {
	Attributes map[string]interface{} `json:"attributes"`
}

// userIDResponse represents the response containing user ID.
type userIDResponse struct {
	ID string `json:"id"`
}

// errorResponse represents an error response from the external service.
type errorResponse struct {
	Code        string `json:"code"`
	Error       string `json:"error"`
	Description string `json:"description"`
}

// IdentifyUser finds a user matching the given identifier attributes.
func (e *externalService) IdentifyUser(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError) {
	e.logger.Debug("Identifying user via external service")

	reqBody := identifyRequest{Attributes: attributes}
	body, err := json.Marshal(reqBody)
	if err != nil {
		e.logger.Error("Failed to marshal identify request", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}

	url := fmt.Sprintf("%s/users/identify", e.baseURL)
	resp, err := e.doRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		e.logger.Error("Failed to call identify user API", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, e.parseErrorResponse(resp.Body, ErrorCodeUserNotFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, e.parseErrorResponse(resp.Body, "")
	}

	var result userIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		e.logger.Error("Failed to decode identify response", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}

	return &result.ID, nil
}

// Authenticate validates the given attributes (identifiers + credentials) and returns the user ID.
func (e *externalService) Authenticate(ctx context.Context, attributes map[string]interface{}) (*string, *serviceerror.ServiceError) {
	e.logger.Debug("Authenticating user via external service")

	reqBody := authenticateRequest{Attributes: attributes}
	body, err := json.Marshal(reqBody)
	if err != nil {
		e.logger.Error("Failed to marshal authenticate request", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}

	url := fmt.Sprintf("%s/users/authenticate", e.baseURL)
	resp, err := e.doRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		e.logger.Error("Failed to call authenticate user API", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, e.parseErrorResponse(resp.Body, ErrorCodeUserNotFound)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, e.parseErrorResponse(resp.Body, ErrorCodeAuthenticationFailed)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, e.parseErrorResponse(resp.Body, "")
	}

	var result userIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		e.logger.Error("Failed to decode authenticate response", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}

	return &result.ID, nil
}

// GetUser retrieves all non-credential attributes for a user by their unique ID.
func (e *externalService) GetUser(ctx context.Context, userID string) (*User, *serviceerror.ServiceError) {
	e.logger.Debug("Getting user via external service", log.String("userID", log.MaskString(userID)))

	url := fmt.Sprintf("%s/users/%s", e.baseURL, userID)
	resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		e.logger.Error("Failed to call get user API", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, e.parseErrorResponse(resp.Body, ErrorCodeUserNotFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, e.parseErrorResponse(resp.Body, "")
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		e.logger.Error("Failed to decode get user response", log.Error(err))
		return nil, &serviceerror.InternalServerError
	}

	return &user, nil
}

// doRequest performs an HTTP request with the given method, URL, and body.
func (e *externalService) doRequest(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return e.httpClient.Do(req)
}

// parseErrorResponse parses an error response from the external service.
func (e *externalService) parseErrorResponse(body io.Reader, defaultCode string) *serviceerror.ServiceError {
	var errResp errorResponse
	if err := json.NewDecoder(body).Decode(&errResp); err != nil {
		e.logger.Error("Failed to decode error response", log.Error(err))
		return &serviceerror.InternalServerError
	}

	code := errResp.Code
	if code == "" {
		code = defaultCode
	}

	return &serviceerror.ServiceError{
		Code:             code,
		Error:            errResp.Error,
		ErrorDescription: errResp.Description,
		Type:             serviceerror.ClientErrorType,
	}
}
