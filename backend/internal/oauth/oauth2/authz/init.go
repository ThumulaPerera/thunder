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

package authz

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/application"
	"github.com/asgardeo/thunder/internal/flow/flowexec"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/jwt"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// Initialize initializes the authorization handler and registers its routes.
func Initialize(
	mux *http.ServeMux,
	applicationService application.ApplicationServiceInterface,
	jwtService jwt.JWTServiceInterface,
	flowExecService flowexec.FlowExecServiceInterface,
) AuthorizeServiceInterface {
	authzCodeStore := newAuthorizationCodeStore(config.GetThunderRuntime().Config.Server.Identifier)
	authzService := newAuthorizeService(authzCodeStore)
	authzHandler := newAuthorizeHandler(applicationService, jwtService, authzCodeStore, flowExecService)
	registerRoutes(mux, authzHandler)
	return authzService
}

// registerRoutes registers the routes for OAuth2 authorization operations.
func registerRoutes(mux *http.ServeMux, authzHandler AuthorizeHandlerInterface) {
	opts := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}

	mux.HandleFunc(middleware.WithCORS("GET /oauth2/authorize",
		authzHandler.HandleAuthorizeGetRequest, opts))
	mux.HandleFunc(middleware.WithCORS("POST /oauth2/authorize",
		authzHandler.HandleAuthorizePostRequest, opts))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /oauth2/authorize",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, opts))
}
