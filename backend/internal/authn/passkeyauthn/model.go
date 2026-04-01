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

package passkeyauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
)

// AuthenticatorSelection represents criteria for selecting authenticators during registration.
type AuthenticatorSelection struct {
	AuthenticatorAttachment string
	RequireResidentKey      bool
	ResidentKey             string
	UserVerification        string
}

// RegistrationStartRequest represents the request to start passkey credential registration.
type RegistrationStartRequest struct {
	UserID                 string
	RelyingPartyID         string
	RelyingPartyName       string
	AuthenticatorSelection *AuthenticatorSelection
	Attestation            string
}

// PublicKeyCredentialCreationOptions represents the options for credential creation.
type PublicKeyCredentialCreationOptions struct {
	Challenge              string                            `json:"challenge"`
	RelyingParty           protocol.RelyingPartyEntity       `json:"rp"`
	User                   protocol.UserEntity               `json:"user"`
	Parameters             []protocol.CredentialParameter    `json:"pubKeyCredParams"`
	AuthenticatorSelection protocol.AuthenticatorSelection   `json:"authenticatorSelection,omitempty"`
	Timeout                int                               `json:"timeout,omitempty"`
	CredentialExcludeList  []protocol.CredentialDescriptor   `json:"excludeCredentials,omitempty"`
	Extensions             protocol.AuthenticationExtensions `json:"extensions,omitempty"`
	Attestation            protocol.ConveyancePreference     `json:"attestation,omitempty"`
}

// RegistrationStartData represents the data returned when initiating passkey registration.
type RegistrationStartData struct {
	PublicKeyCredentialCreationOptions PublicKeyCredentialCreationOptions `json:"publicKeyCredentialCreationOptions"`
	SessionToken                       string                             `json:"sessionToken"`
}

// RegistrationFinishRequest represents the request to finish passkey credential registration.
type RegistrationFinishRequest struct {
	CredentialID      string
	CredentialType    string
	ClientDataJSON    string
	AttestationObject string
	SessionToken      string
	CredentialName    string
}

// RegistrationFinishData represents the data returned after completing passkey registration.
type RegistrationFinishData struct {
	CredentialID   string
	CredentialName string
	CreatedAt      string
}

// AuthenticationStartRequest represents the request to start passkey authentication.
type AuthenticationStartRequest struct {
	UserID         string
	RelyingPartyID string
}

// PublicKeyCredentialRequestOptions represents the options for credential assertion.
type PublicKeyCredentialRequestOptions struct {
	Challenge        string                               `json:"challenge"`
	Timeout          int                                  `json:"timeout,omitempty"`
	RelyingPartyID   string                               `json:"rpId,omitempty"`
	AllowCredentials []protocol.CredentialDescriptor      `json:"allowCredentials,omitempty"`
	UserVerification protocol.UserVerificationRequirement `json:"userVerification,omitempty"`
	Extensions       protocol.AuthenticationExtensions    `json:"extensions,omitempty"`
}

// AuthenticationStartData represents the data returned when initiating passkey authentication.
type AuthenticationStartData struct {
	PublicKeyCredentialRequestOptions PublicKeyCredentialRequestOptions `json:"publicKeyCredentialRequestOptions"`
	SessionToken                      string                            `json:"sessionToken"`
}

// AuthenticationFinishRequest represents the request to finish passkey authentication.
type AuthenticationFinishRequest struct {
	CredentialID      string
	CredentialType    string
	ClientDataJSON    string
	AuthenticatorData string
	Signature         string
	UserHandle        string
	SessionToken      string
}

