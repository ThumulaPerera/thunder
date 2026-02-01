/*
 * External User Service
 *
 * A proxy server that implements the External User Service REST API
 * and forwards requests to Thunder's internal REST APIs.
 */

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	serverPort     = ":8091"
	thunderBaseURL = "https://localhost:8090"
)

type IdentifyRequest struct {
	Attributes map[string]interface{} `json:"attributes"`
}

type AuthenticateRequest struct {
	Attributes map[string]interface{} `json:"attributes"`
}

type UserIDResponse struct {
	ID string `json:"id"`
}

type User struct {
	ID               string                 `json:"id"`
	OrganizationUnit string                 `json:"organizationUnit"`
	Type             string                 `json:"type"`
	Attributes       map[string]interface{} `json:"attributes"`
}

type ErrorResponse struct {
	Code        string `json:"code"`
	Error       string `json:"error"`
	Description string `json:"description"`
}

// Thunder API response types
type thunderUserListResponse struct {
	TotalResults int    `json:"totalResults"`
	Users        []User `json:"users"`
}

type thunderAuthResponse struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	OrganizationUnit string `json:"organization_unit"`
}

var thunderClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func main() {
	http.HandleFunc("/users/identify", handleIdentifyUser)
	http.HandleFunc("/users/authenticate", handleAuthenticateUser)
	http.HandleFunc("/users/", handleGetUser)
	http.HandleFunc("/health", handleHealth)

	log.Printf("External User Service starting on http://localhost%s", serverPort)
	log.Printf("Proxying to Thunder server at %s", thunderBaseURL)
	log.Fatal(http.ListenAndServe(serverPort, nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleIdentifyUser handles POST /users/identify
// Maps to Thunder's GET /users?filter=<scim-filter>
func handleIdentifyUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IdentifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "EXTSVC-4000", "bad_request", "Invalid request body")
		return
	}

	log.Printf("IdentifyUser: %+v", req.Attributes)

	// Build SCIM filter from attributes
	// Example: username eq "john" becomes "username eq \"john\""
	filter := buildSCIMFilter(req.Attributes)
	if filter == "" {
		sendError(w, http.StatusBadRequest, "EXTSVC-4000", "bad_request", "No searchable attributes provided")
		return
	}

	// Call Thunder's user list API with filter
	escapedFilter := url.QueryEscape(filter)
	thunderURL := fmt.Sprintf("%s/users?filter=%s&limit=1", thunderBaseURL, escapedFilter)

	httpReq, _ := http.NewRequest(http.MethodGet, thunderURL, nil)
	resp, err := thunderClient.Do(httpReq)
	if err != nil {
		log.Printf("Error calling Thunder: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to call user service")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Thunder error: %d - %s", resp.StatusCode, string(body))
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "User service error")
		return
	}

	var listResp thunderUserListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		log.Printf("Error decoding response: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to parse response")
		return
	}

	if listResp.TotalResults == 0 || len(listResp.Users) == 0 {
		sendError(w, http.StatusNotFound, "EXTSVC-1001", "user_not_found", "No user found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserIDResponse{ID: listResp.Users[0].ID})
}

// handleAuthenticateUser handles POST /users/authenticate
// Maps to Thunder's POST /auth/credentials/authenticate
func handleAuthenticateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "EXTSVC-4000", "bad_request", "Invalid request body")
		return
	}

	log.Printf("AuthenticateUser: %v", req.Attributes["username"])

	// Call Thunder's credential authentication endpoint
	thunderURL := fmt.Sprintf("%s/auth/credentials/authenticate", thunderBaseURL)

	// Add skip_assertion to avoid generating JWT
	authReq := make(map[string]interface{})
	for k, v := range req.Attributes {
		authReq[k] = v
	}
	authReq["skip_assertion"] = true

	body, _ := json.Marshal(authReq)

	resp, err := thunderClient.Post(thunderURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("Error calling Thunder: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to call user service")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		sendError(w, http.StatusNotFound, "EXTSVC-1001", "user_not_found", "No user found")
		return
	}

	if resp.StatusCode == http.StatusUnauthorized {
		sendError(w, http.StatusUnauthorized, "EXTSVC-1002", "authentication_failed", "Invalid credentials")
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Thunder error: %d - %s", resp.StatusCode, string(body))
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "User service error")
		return
	}

	var authResp thunderAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		log.Printf("Error decoding response: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to parse response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserIDResponse{ID: authResp.ID})
}

// handleGetUser handles GET /users/{id}
// Maps to Thunder's GET /users/{id}
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/users/")
	userID := strings.TrimSuffix(path, "/")

	if userID == "" || userID == "identify" || userID == "authenticate" {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	log.Printf("GetUser: %s", userID)

	thunderURL := fmt.Sprintf("%s/users/%s", thunderBaseURL, userID)
	req, _ := http.NewRequest(http.MethodGet, thunderURL, nil)
	resp, err := thunderClient.Do(req)
	if err != nil {
		log.Printf("Error calling Thunder: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to call user service")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		sendError(w, http.StatusNotFound, "EXTSVC-1001", "user_not_found", "User not found")
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Thunder error: %d - %s", resp.StatusCode, string(body))
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "User service error")
		return
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Printf("Error decoding response: %v", err)
		sendError(w, http.StatusInternalServerError, "EXTSVC-5000", "internal_error", "Failed to parse response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// buildSCIMFilter creates a SCIM filter from attributes
// Example: {"username": "john"} -> "username eq \"john\""
func buildSCIMFilter(attributes map[string]interface{}) string {
	var filters []string

	// Only use simple string attributes for filtering
	for key, value := range attributes {
		if strVal, ok := value.(string); ok {
			// Escape quotes in the value
			escapedVal := strings.ReplaceAll(strVal, `"`, `\"`)
			filters = append(filters, fmt.Sprintf(`%s eq "%s"`, key, escapedVal))
		}
	}

	if len(filters) == 0 {
		return ""
	}

	// Join with AND
	return strings.Join(filters, " and ")
}

func sendError(w http.ResponseWriter, statusCode int, code, errorType, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:        code,
		Error:       errorType,
		Description: description,
	})
}
