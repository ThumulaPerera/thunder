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

package executor

import (
	"context"
	"slices"

	"github.com/asgardeo/thunder/internal/externalsvc"
	"github.com/asgardeo/thunder/internal/flow/common"
	"github.com/asgardeo/thunder/internal/flow/core"
	"github.com/asgardeo/thunder/internal/system/log"
)

const (
	idfExecExternalLoggerComponentName = "IdentifyingExecutorExternal"
	ExecutorNameIdentifyingExternal    = "IdentifyingExecutorExternal"
)

// identifyingExecutorExternalInterface defines the interface for identifying executors with external service.
type identifyingExecutorExternalInterface interface {
	IdentifyUser(filters map[string]interface{},
		execResp *common.ExecutorResponse) (*string, error)
}

// identifyingExecutorExternal implements the ExecutorInterface for identifying users based on provided attributes.
type identifyingExecutorExternal struct {
	core.ExecutorInterface
	externalSvc externalsvc.ExternalSvcInterface
	logger      *log.Logger
}

var _ core.ExecutorInterface = (*identifyingExecutorExternal)(nil)
var _ identifyingExecutorExternalInterface = (*identifyingExecutorExternal)(nil)

// newIdentifyingExecutorExternal creates a new instance of IdentifyingExecutorExternal.
func newIdentifyingExecutorExternal(
	name string,
	defaultInputs, prerequisites []common.Input,
	flowFactory core.FlowFactoryInterface,
	externalSvc externalsvc.ExternalSvcInterface,
) *identifyingExecutorExternal {
	if name == "" {
		name = ExecutorNameIdentifyingExternal
	}
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, idfExecExternalLoggerComponentName),
		log.String(log.LoggerKeyExecutorName, name))

	base := flowFactory.CreateExecutor(ExecutorNameIdentifyingExternal, common.ExecutorTypeUtility,
		defaultInputs, prerequisites)
	return &identifyingExecutorExternal{
		ExecutorInterface: base,
		externalSvc:       externalSvc,
		logger:            logger,
	}
}

// IdentifyUser identifies a user based on the provided attributes.
func (i *identifyingExecutorExternal) IdentifyUser(filters map[string]interface{},
	execResp *common.ExecutorResponse) (*string, error) {
	logger := i.logger
	logger.Debug("Identifying user with filters")

	// filter out non-searchable attributes
	var searchableFilter = make(map[string]interface{})
	for key, value := range filters {
		if !slices.Contains(nonSearchableInputs, key) {
			searchableFilter[key] = value
		}
	}

	userID, svcErr := i.externalSvc.IdentifyUser(context.TODO(), searchableFilter)
	if svcErr != nil {
		if svcErr.Code == externalsvc.ErrorCodeUserNotFound {
			logger.Debug("User not found for the provided filters")
			execResp.Status = common.ExecFailure
			execResp.FailureReason = failureReasonUserNotFound
			return nil, nil
		} else {
			logger.Debug("Failed to identify user due to error: " + svcErr.Error)
			execResp.Status = common.ExecFailure
			execResp.FailureReason = failureReasonFailedToIdentifyUser
			return nil, nil
		}
	}

	if userID == nil || *userID == "" {
		logger.Debug("User not found for the provided filter")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonUserNotFound
		return nil, nil
	}

	return userID, nil
}

// Execute executes the identifying executor logic.
func (i *identifyingExecutorExternal) Execute(ctx *core.NodeContext) (*common.ExecutorResponse, error) {
	logger := i.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing identifying executor")

	execResp := &common.ExecutorResponse{
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}

	// Check if required inputs are provided
	if !i.HasRequiredInputs(ctx, execResp) {
		logger.Debug("Required inputs for identifying executor are not provided")
		execResp.Status = common.ExecUserInputRequired
		return execResp, nil
	}

	userSearchAttributes := map[string]interface{}{}

	for _, inputData := range i.GetRequiredInputs(ctx) {
		if value, ok := ctx.UserInputs[inputData.Identifier]; ok {
			userSearchAttributes[inputData.Identifier] = value
		} else if value, ok := ctx.RuntimeData[inputData.Identifier]; ok {
			// Fallback to RuntimeData if not in UserInputs
			userSearchAttributes[inputData.Identifier] = value
		}
	}

	// Try to identify the user
	userID, err := i.IdentifyUser(userSearchAttributes, execResp)

	if err != nil {
		logger.Debug("Failed to identify user due to error: " + err.Error())
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonFailedToIdentifyUser
		return execResp, nil
	}

	if userID == nil || *userID == "" {
		logger.Debug("User not found for the provided attributes")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonUserNotFound
		return execResp, nil
	}

	// Store the resolved userID in RuntimeData for subsequent executors
	execResp.RuntimeData[userAttributeUserID] = *userID
	execResp.Status = common.ExecComplete

	logger.Debug("Identifying executor completed successfully",
		log.String("userID", log.MaskString(*userID)))

	return execResp, nil
}
