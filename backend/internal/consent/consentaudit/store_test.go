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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/tests/mocks/database/providermock"
)

const testDeploymentID = "test-deployment"

type StoreTestSuite struct {
	suite.Suite
	mockDBProvider *providermock.DBProviderInterfaceMock
	mockDBClient   *providermock.DBClientInterfaceMock
	store          *consentAuditStore
}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}

func (s *StoreTestSuite) SetupTest() {
	s.mockDBProvider = providermock.NewDBProviderInterfaceMock(s.T())
	s.mockDBClient = providermock.NewDBClientInterfaceMock(s.T())
	s.store = &consentAuditStore{
		dbProvider:   s.mockDBProvider,
		deploymentID: testDeploymentID,
	}
}

func sampleRecord() consentAuditRecord {
	return consentAuditRecord{
		ID:             "audit-1",
		Action:         "CONSENT_CREATED",
		ConsentID:      "consent-1",
		GroupID:        "app1",
		SubjectUserIDs: `["user1"]`,
		ActorID:        nil,
		TraceID:        "trace-xyz",
		Details:        `{"status":"active"}`,
	}
}

// anyArgs returns the matchers for ExecuteContext: ctx, the query, and its 10 unrolled insert args.
func anyArgs() []interface{} {
	matchers := []interface{}{mock.Anything, QueryCreateConsentAudit}
	for i := 0; i < 10; i++ {
		matchers = append(matchers, mock.Anything)
	}
	return matchers
}

func (s *StoreTestSuite) TestCreateConsentAudit_Success() {
	s.mockDBProvider.On("GetOperationDBClient").Return(s.mockDBClient, nil)

	var call mock.Arguments
	s.mockDBClient.On("ExecuteContext", anyArgs()...).
		Run(func(callArgs mock.Arguments) { call = callArgs }).
		Return(int64(1), nil)

	err := s.store.CreateConsentAudit(context.Background(), sampleRecord())

	s.NoError(err)
	// Unrolled call: [ctx, query, ID, ACTION, CONSENT_ID, GROUP_ID, SUBJECT_USER_IDS, ACTOR_ID,
	// TRACE_ID, DETAILS, DEPLOYMENT_ID, CREATED_AT].
	s.Equal("audit-1", call.Get(2))
	s.Equal("CONSENT_CREATED", call.Get(3))
	s.Equal("consent-1", call.Get(4))
	s.Equal("app1", call.Get(5))
	s.Equal(`["user1"]`, call.Get(6))
	s.Nil(call.Get(7)) // actor is NULL
	s.Equal("trace-xyz", call.Get(8))
	s.Equal(`{"status":"active"}`, call.Get(9))
	s.Equal(testDeploymentID, call.Get(10))
	s.IsType(time.Time{}, call.Get(11))
}

func (s *StoreTestSuite) TestCreateConsentAudit_ClientError() {
	s.mockDBProvider.On("GetOperationDBClient").Return(nil, errors.New("no client"))

	err := s.store.CreateConsentAudit(context.Background(), sampleRecord())

	s.Error(err)
}

func (s *StoreTestSuite) TestCreateConsentAudit_ExecuteError() {
	s.mockDBProvider.On("GetOperationDBClient").Return(s.mockDBClient, nil)
	s.mockDBClient.On("ExecuteContext", anyArgs()...).
		Return(int64(0), errors.New("insert failed"))

	err := s.store.CreateConsentAudit(context.Background(), sampleRecord())

	s.Error(err)
}
