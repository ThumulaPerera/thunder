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
	authnprovidercm "github.com/asgardeo/thunder/internal/authnprovider/common"
	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

// PasskeyAuthnServiceInterface defines the interface for passkey authentication operations.
type PasskeyAuthnServiceInterface interface {
	StartRegistration(ctx context.Context, req *RegistrationStartRequest) (
		*RegistrationStartData, *serviceerror.ServiceError)
	FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (
		*RegistrationFinishData, *serviceerror.ServiceError)
	StartAuthentication(ctx context.Context, req *AuthenticationStartRequest) (
		*AuthenticationStartData, *serviceerror.ServiceError)
	FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (
		*authnprovidercm.AuthnResult, *serviceerror.ServiceError)
}

type passkeyAuthnService struct {
	passkeyService passkey.PasskeyServiceInterface
	authnProvider  authnprovidermgr.AuthnProviderManagerInterface
	logger         *log.Logger
}

func newPasskeyAuthnService(
	passkeySvc passkey.PasskeyServiceInterface,
	authnProvider authnprovidermgr.AuthnProviderManagerInterface,
) PasskeyAuthnServiceInterface {
	service := &passkeyAuthnService{
		passkeyService: passkeySvc,
		authnProvider:  authnProvider,
		logger:         log.GetLogger().With(log.String(log.LoggerKeyComponentName, "PasskeyAuthnService")),
	}
	common.RegisterAuthenticator(service.getMetadata())
	return service
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
		if svcErr.Type == serviceerror.ClientErrorType {
			switch svcErr.Code {
			case passkey.ErrorInvalidFinishData.Code:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorEmptyUserIdentifier.Code:
				return nil, newClientError(ErrorEmptyUserIdentifier.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorEmptyRelyingPartyID.Code:
				return nil, newClientError(ErrorEmptyRelyingPartyID.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorUserNotFound.Code:
				return nil, newClientError(ErrorUserNotFound.Code, svcErr.Error, svcErr.ErrorDescription)
			default:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			}
		}
		return nil, s.logAndReturnServerError("StartRegistration failed with server error",
			log.String("relyingPartyID", req.RelyingPartyID))
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
		if svcErr.Type == serviceerror.ClientErrorType {
			switch svcErr.Code {
			case passkey.ErrorInvalidFinishData.Code:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorEmptySessionToken.Code:
				return nil, newClientError(ErrorEmptySessionToken.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorInvalidAttestationResponse.Code:
				return nil, newClientError(ErrorInvalidAttestationResponse.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorInvalidSessionToken.Code:
				return nil, newClientError(ErrorInvalidSessionToken.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorSessionExpired.Code:
				return nil, newClientError(ErrorSessionExpired.Code, svcErr.Error, svcErr.ErrorDescription)
			default:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			}
		}
		return nil, s.logAndReturnServerError("FinishRegistration failed with server error")
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
		if svcErr.Type == serviceerror.ClientErrorType {
			switch svcErr.Code {
			case passkey.ErrorInvalidFinishData.Code:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorEmptyRelyingPartyID.Code:
				return nil, newClientError(ErrorEmptyRelyingPartyID.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorUserNotFound.Code:
				return nil, newClientError(ErrorUserNotFound.Code, svcErr.Error, svcErr.ErrorDescription)
			case passkey.ErrorNoCredentialsFound.Code:
				return nil, newClientError(ErrorNoCredentialsFound.Code, svcErr.Error, svcErr.ErrorDescription)
			default:
				return nil, newClientError(ErrorInvalidFinishData.Code, svcErr.Error, svcErr.ErrorDescription)
			}
		}
		return nil, s.logAndReturnServerError("StartAuthentication failed with server error",
			log.String("relyingPartyID", req.RelyingPartyID))
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
) (*authnprovidercm.AuthnResult, *serviceerror.ServiceError) {
	passkeyCredential := &passkey.PasskeyAuthenticationFinishRequest{
		CredentialID:      req.CredentialID,
		CredentialType:    req.CredentialType,
		ClientDataJSON:    req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData,
		Signature:         req.Signature,
		UserHandle:        req.UserHandle,
		SessionToken:      req.SessionToken,
	}
	credentials := map[string]interface{}{
		"passkey": passkeyCredential,
	}

	authnResult, err := s.authnProvider.Authenticate(ctx, nil, credentials, nil)
	if err != nil {
		if err.Type == serviceerror.ClientErrorType {
			switch err.Code {
			case authnprovidercm.ErrorCodeAuthenticationFailed:
				return nil, newClientError(ErrorAuthenticationFailed.Code, err.Error, err.ErrorDescription)
			case authnprovidercm.ErrorCodeInvalidRequest:
				return nil, newClientError(ErrorInvalidRequest.Code, err.Error, err.ErrorDescription)
			case authnprovidercm.ErrorCodeUserNotFound:
				return nil, newClientError(ErrorUserNotFound.Code, err.Error, err.ErrorDescription)
			default:
				return nil, newClientError(ErrorAuthenticationFailed.Code, err.Error, err.ErrorDescription)
			}
		}
		return nil, s.logAndReturnServerError("FinishAuthentication failed with server error")
	}
	return authnResult, nil
}

func newClientError(code, msg, desc string) *serviceerror.ServiceError {
	return &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             code,
		Error:            msg,
		ErrorDescription: desc,
	}
}

func (s *passkeyAuthnService) logAndReturnServerError(msg string, fields ...log.Field) *serviceerror.ServiceError {
	s.logger.Error(msg, fields...)
	return &serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-PSKAUTHN-0001",
		Error:            "System error",
		ErrorDescription: "An internal server error occurred",
	}
}

func (s *passkeyAuthnService) getMetadata() common.AuthenticatorMeta {
	return common.AuthenticatorMeta{
		Name:    common.AuthenticatorPasskey,
		Factors: []common.AuthenticationFactor{common.FactorPossession, common.FactorInherence},
	}
}
