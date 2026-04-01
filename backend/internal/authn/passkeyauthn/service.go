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
	"context"

	"github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/authn/passkey"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
)

// PasskeyAuthnServiceInterface defines the interface for passkey authentication operations.
type PasskeyAuthnServiceInterface interface {
	StartRegistration(ctx context.Context, req *RegistrationStartRequest) (*RegistrationStartData, *serviceerror.ServiceError)
	FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (*RegistrationFinishData, *serviceerror.ServiceError)
	StartAuthentication(ctx context.Context, req *AuthenticationStartRequest) (*AuthenticationStartData, *serviceerror.ServiceError)
	FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (*common.AuthenticationResponse, *serviceerror.ServiceError)
}

type passkeyAuthnService struct {
	passkeyService passkey.PasskeyServiceInterface
}

func newPasskeyAuthnService(passkeySvc passkey.PasskeyServiceInterface) PasskeyAuthnServiceInterface {
	return &passkeyAuthnService{passkeyService: passkeySvc}
}

func (s *passkeyAuthnService) StartRegistration(
	ctx context.Context, req *RegistrationStartRequest,
) (*RegistrationStartData, *serviceerror.ServiceError) {
	var passkeyAuthSel *passkey.AuthenticatorSelection
	if req.AuthenticatorSelection != nil {
		passkeyAuthSel = &passkey.AuthenticatorSelection{
			AuthenticatorAttachment: req.AuthenticatorSelection.AuthenticatorAttachment,
			RequireResidentKey:      req.AuthenticatorSelection.RequireResidentKey,
			ResidentKey:             req.AuthenticatorSelection.ResidentKey,
			UserVerification:        req.AuthenticatorSelection.UserVerification,
		}
	}
	data, svcErr := s.passkeyService.StartRegistration(ctx, &passkey.PasskeyRegistrationStartRequest{
		UserID:                 req.UserID,
		RelyingPartyID:         req.RelyingPartyID,
		RelyingPartyName:       req.RelyingPartyName,
		AuthenticatorSelection: passkeyAuthSel,
		Attestation:            req.Attestation,
	})
	if svcErr != nil {
		return nil, svcErr
	}
	return &RegistrationStartData{
		SessionToken: data.SessionToken,
		PublicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions{
			Challenge:              data.PublicKeyCredentialCreationOptions.Challenge,
			RelyingParty:           data.PublicKeyCredentialCreationOptions.RelyingParty,
			User:                   data.PublicKeyCredentialCreationOptions.User,
			Parameters:             data.PublicKeyCredentialCreationOptions.Parameters,
			AuthenticatorSelection: data.PublicKeyCredentialCreationOptions.AuthenticatorSelection,
			Timeout:                data.PublicKeyCredentialCreationOptions.Timeout,
			CredentialExcludeList:  data.PublicKeyCredentialCreationOptions.CredentialExcludeList,
			Extensions:             data.PublicKeyCredentialCreationOptions.Extensions,
			Attestation:            data.PublicKeyCredentialCreationOptions.Attestation,
		},
	}, nil
}

func (s *passkeyAuthnService) FinishRegistration(
	ctx context.Context, req *RegistrationFinishRequest,
) (*RegistrationFinishData, *serviceerror.ServiceError) {
	data, svcErr := s.passkeyService.FinishRegistration(ctx, &passkey.PasskeyRegistrationFinishRequest{
		CredentialID:      req.CredentialID,
		CredentialType:    req.CredentialType,
		ClientDataJSON:    req.ClientDataJSON,
		AttestationObject: req.AttestationObject,
		SessionToken:      req.SessionToken,
		CredentialName:    req.CredentialName,
	})
	if svcErr != nil {
		return nil, svcErr
	}
	return &RegistrationFinishData{
		CredentialID:   data.CredentialID,
		CredentialName: data.CredentialName,
		CreatedAt:      data.CreatedAt,
	}, nil
}

func (s *passkeyAuthnService) StartAuthentication(
	ctx context.Context, req *AuthenticationStartRequest,
) (*AuthenticationStartData, *serviceerror.ServiceError) {
	data, svcErr := s.passkeyService.StartAuthentication(ctx, &passkey.PasskeyAuthenticationStartRequest{
		UserID:         req.UserID,
		RelyingPartyID: req.RelyingPartyID,
	})
	if svcErr != nil {
		return nil, svcErr
	}
	return &AuthenticationStartData{
		SessionToken: data.SessionToken,
		PublicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions{
			Challenge:        data.PublicKeyCredentialRequestOptions.Challenge,
			Timeout:          data.PublicKeyCredentialRequestOptions.Timeout,
			RelyingPartyID:   data.PublicKeyCredentialRequestOptions.RelyingPartyID,
			AllowCredentials: data.PublicKeyCredentialRequestOptions.AllowCredentials,
			UserVerification: data.PublicKeyCredentialRequestOptions.UserVerification,
			Extensions:       data.PublicKeyCredentialRequestOptions.Extensions,
		},
	}, nil
}

func (s *passkeyAuthnService) FinishAuthentication(
	ctx context.Context, req *AuthenticationFinishRequest,
) (*common.AuthenticationResponse, *serviceerror.ServiceError) {
	return s.passkeyService.FinishAuthentication(ctx, &passkey.PasskeyAuthenticationFinishRequest{
		CredentialID:      req.CredentialID,
		CredentialType:    req.CredentialType,
		ClientDataJSON:    req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData,
		Signature:         req.Signature,
		UserHandle:        req.UserHandle,
		SessionToken:      req.SessionToken,
	})
}
