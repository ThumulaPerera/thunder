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
	"fmt"

	"github.com/thunder-id/thunderid/internal/consent"
	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/transaction"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

// consentAuditService is the database-backed implementation of consent.ConsentAuditProvider.
type consentAuditService struct {
	store         consentAuditStoreInterface
	transactioner transaction.Transactioner
}

var _ consent.ConsentAuditProvider = (*consentAuditService)(nil)

// newConsentAuditService constructs the database-backed consent auditor.
func newConsentAuditService(
	store consentAuditStoreInterface,
	transactioner transaction.Transactioner,
) consent.ConsentAuditProvider {
	return &consentAuditService{
		store:         store,
		transactioner: transactioner,
	}
}

// auditDetails is the JSON snapshot of the consent state stored in the DETAILS column.
type auditDetails struct {
	Status         string                         `json:"status"`
	ValidityTime   int64                          `json:"validityTime"`
	Purposes       []consent.ConsentPurposeItem   `json:"purposes"`
	Authorizations []consent.ConsentAuthorization `json:"authorizations"`
}

// Record persists a consent audit record.
func (s *consentAuditService) Record(ctx context.Context, entry consent.ConsentAuditEntry) error {
	id, err := utils.GenerateUUIDv7()
	if err != nil {
		return fmt.Errorf("failed to generate consent audit ID: %w", err)
	}

	subjectUserIDs, err := marshalJSON(entry.SubjectUserIDs)
	if err != nil {
		return err
	}
	details, err := marshalJSON(auditDetails{
		Status:         string(entry.Status),
		ValidityTime:   entry.ValidityTime,
		Purposes:       entry.Purposes,
		Authorizations: entry.Authorizations,
	})
	if err != nil {
		return err
	}

	// The acting principal is not available today, so ACTOR_ID is stored as NULL.
	var actorID interface{}

	rec := consentAuditRecord{
		ID:             id,
		Action:         string(entry.Action),
		ConsentID:      entry.ConsentID,
		GroupID:        entry.GroupID,
		SubjectUserIDs: subjectUserIDs,
		ActorID:        actorID,
		TraceID:        syscontext.GetTraceID(ctx),
		Details:        details,
	}

	return s.transactioner.Transact(ctx, func(txCtx context.Context) error {
		return s.store.CreateConsentAudit(txCtx, rec)
	})
}

// marshalJSON serializes a value for storage in a JSON column.
func marshalJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal consent audit data: %w", err)
	}
	return string(data), nil
}
