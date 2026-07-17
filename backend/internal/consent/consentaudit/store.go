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
	"fmt"
	"time"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/database/provider"
	"github.com/thunder-id/thunderid/internal/system/transaction"
)

// consentAuditRecord is the persistence-shaped consent audit record.
type consentAuditRecord struct {
	ID             string
	Action         string
	ConsentID      string
	GroupID        string
	SubjectUserIDs string
	ActorID        interface{}
	TraceID        string
	Details        string
}

// consentAuditStoreInterface defines the persistence operations for consent audit records.
type consentAuditStoreInterface interface {
	CreateConsentAudit(ctx context.Context, rec consentAuditRecord) error
}

// consentAuditStore is the default database-backed implementation of consentAuditStoreInterface.
type consentAuditStore struct {
	dbProvider   provider.DBProviderInterface
	deploymentID string
}

// newConsentAuditStore creates a new consentAuditStore along with a transactioner that the service
// uses to enroll the audit write in the caller's transaction.
func newConsentAuditStore() (consentAuditStoreInterface, transaction.Transactioner, error) {
	dbProvider := provider.GetDBProvider()

	transactioner, err := dbProvider.GetOperationDBTransactioner()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get transactioner: %w", err)
	}

	return &consentAuditStore{
		dbProvider:   dbProvider,
		deploymentID: config.GetServerRuntime().Config.Server.Identifier,
	}, transactioner, nil
}

// CreateConsentAudit persists a consent audit record.
func (s *consentAuditStore) CreateConsentAudit(ctx context.Context, rec consentAuditRecord) error {
	dbClient, err := s.dbProvider.GetOperationDBClient()
	if err != nil {
		return fmt.Errorf("failed to get database client: %w", err)
	}

	if _, err := dbClient.ExecuteContext(
		ctx,
		QueryCreateConsentAudit,
		rec.ID,
		rec.Action,
		rec.ConsentID,
		rec.GroupID,
		rec.SubjectUserIDs,
		rec.ActorID,
		rec.TraceID,
		rec.Details,
		s.deploymentID,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("failed to record consent audit: %w", err)
	}

	return nil
}
