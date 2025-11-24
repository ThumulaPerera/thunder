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

package branding

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/middleware"
)

// Initialize initializes the branding service and registers its routes.
func Initialize(mux *http.ServeMux) BrandingServiceInterface {
	brandingStore := newBrandingStore(config.GetThunderRuntime().Config.Server.Identifier)
	brandingService := newBrandingService(brandingStore)
	brandingHandler := newBrandingHandler(brandingService)
	registerRoutes(mux, brandingHandler)
	return brandingService
}

// registerRoutes registers the routes for branding management operations.
func registerRoutes(mux *http.ServeMux, brandingHandler *brandingHandler) {
	opts1 := middleware.CORSOptions{
		AllowedMethods:   "GET, POST",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("POST /branding", brandingHandler.HandleBrandingPostRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("GET /branding", brandingHandler.HandleBrandingListRequest, opts1))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /branding", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, opts1))

	opts2 := middleware.CORSOptions{
		AllowedMethods:   "GET, PUT, DELETE",
		AllowedHeaders:   "Content-Type, Authorization",
		AllowCredentials: true,
	}
	mux.HandleFunc(middleware.WithCORS("GET /branding/{id}", brandingHandler.HandleBrandingGetRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("PUT /branding/{id}", brandingHandler.HandleBrandingPutRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("DELETE /branding/{id}", brandingHandler.HandleBrandingDeleteRequest, opts2))
	mux.HandleFunc(middleware.WithCORS("OPTIONS /branding/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, opts2))
}
