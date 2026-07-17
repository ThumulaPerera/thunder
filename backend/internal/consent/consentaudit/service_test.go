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

package consentaudit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/consent"
	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/transaction"
)

type ServiceTestSuite struct {
	suite.Suite
	mockStore *consentAuditStoreInterfaceMock
	service   consent.ConsentAuditProvider
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (s *ServiceTestSuite) SetupTest() {
	s.mockStore = newConsentAuditStoreInterfaceMock(s.T())
	s.service = newConsentAuditService(s.mockStore, transaction.NewNoOpTransactioner())
}

func (s *ServiceTestSuite) sampleEntry() consent.ConsentAuditEntry {
	return consent.ConsentAuditEntry{
		Action:         consent.ConsentAuditActionCreated,
		ConsentID:      "consent-1",
		GroupID:        "app1",
		SubjectUserIDs: []string{"user1"},
		Status:         consent.ConsentStatusActive,
		ValidityTime:   0,
		Purposes: []consent.ConsentPurposeItem{
			{Name: "attributes:app1", Elements: []consent.ConsentElementApproval{
				{Name: "email", Namespace: consent.NamespaceAttribute, IsUserApproved: true},
			}},
		},
		Authorizations: []consent.ConsentAuthorization{
			{ID: "auth-1", UserID: "user1", Type: consent.AuthorizationTypeAuthorization,
				Status: consent.AuthorizationStatusApproved, UpdatedTime: 123},
		},
	}
}

func (s *ServiceTestSuite) TestRecord_Success() {
	var got consentAuditRecord
	s.mockStore.EXPECT().CreateConsentAudit(mock.Anything, mock.Anything).
		Run(func(_ context.Context, rec consentAuditRecord) { got = rec }).
		Return(nil)

	ctx := syscontext.WithTraceID(context.Background(), "trace-xyz")
	err := s.service.Record(ctx, s.sampleEntry())

	s.NoError(err)
	s.NotEmpty(got.ID)
	s.Equal(string(consent.ConsentAuditActionCreated), got.Action)
	s.Equal("consent-1", got.ConsentID)
	s.Equal("app1", got.GroupID)
	s.Equal(`["user1"]`, got.SubjectUserIDs)
	s.Nil(got.ActorID)
	s.Equal("trace-xyz", got.TraceID)

	var details auditDetails
	s.NoError(json.Unmarshal([]byte(got.Details), &details))
	s.Equal(string(consent.ConsentStatusActive), details.Status)
	s.Len(details.Purposes, 1)
	s.Len(details.Authorizations, 1)
	s.Equal("user1", details.Authorizations[0].UserID)
}

func (s *ServiceTestSuite) TestRecord_StoreError() {
	s.mockStore.EXPECT().CreateConsentAudit(mock.Anything, mock.Anything).
		Return(errors.New("insert failed"))

	err := s.service.Record(context.Background(), s.sampleEntry())

	s.Error(err)
}
