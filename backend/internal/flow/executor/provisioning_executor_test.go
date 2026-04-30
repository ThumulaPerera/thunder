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
	i18ncore "github.com/asgardeo/thunder/internal/system/i18n/core"

	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	authnprovidermgr "github.com/asgardeo/thunder/internal/authnprovider/manager"
	"github.com/asgardeo/thunder/internal/entityprovider"
	"github.com/asgardeo/thunder/internal/flow/common"
	"github.com/asgardeo/thunder/internal/flow/core"
	"github.com/asgardeo/thunder/internal/group"
	"github.com/asgardeo/thunder/internal/role"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/userschema"
	"github.com/asgardeo/thunder/tests/mocks/authnprovider/managermock"
	"github.com/asgardeo/thunder/tests/mocks/entityprovidermock"
	"github.com/asgardeo/thunder/tests/mocks/flow/coremock"
	"github.com/asgardeo/thunder/tests/mocks/groupmock"
	"github.com/asgardeo/thunder/tests/mocks/rolemock"
	"github.com/asgardeo/thunder/tests/mocks/userschemamock"
)

const (
	testUserType  = "INTERNAL"
	testNewUserID = "user-new"
)

type ProvisioningExecutorTestSuite struct {
	suite.Suite
	mockGroupService      *groupmock.GroupServiceInterfaceMock
	mockRoleService       *rolemock.RoleServiceInterfaceMock
	mockFlowFactory       *coremock.FlowFactoryInterfaceMock
	mockEntityProvider    *entityprovidermock.EntityProviderInterfaceMock
	mockUserSchemaService *userschemamock.UserSchemaServiceInterfaceMock
	mockAuthnProvider     *managermock.AuthnProviderManagerInterfaceMock
	executor              *provisioningExecutor
}

func TestProvisioningExecutorSuite(t *testing.T) {
	suite.Run(t, new(ProvisioningExecutorTestSuite))
}

func (suite *ProvisioningExecutorTestSuite) SetupTest() {
	suite.mockGroupService = groupmock.NewGroupServiceInterfaceMock(suite.T())
	suite.mockRoleService = rolemock.NewRoleServiceInterfaceMock(suite.T())
	suite.mockFlowFactory = coremock.NewFlowFactoryInterfaceMock(suite.T())
	suite.mockEntityProvider = entityprovidermock.NewEntityProviderInterfaceMock(suite.T())
	suite.mockUserSchemaService = userschemamock.NewUserSchemaServiceInterfaceMock(suite.T())
	suite.mockAuthnProvider = managermock.NewAuthnProviderManagerInterfaceMock(suite.T())

	// Mock the embedded identifying executor first
	identifyingMock := suite.createMockIdentifyingExecutor()
	suite.mockFlowFactory.On("CreateExecutor", ExecutorNameIdentifying, common.ExecutorTypeUtility,
		mock.Anything, mock.Anything).Return(identifyingMock).Maybe()

	mockExec := suite.createMockProvisioningExecutor()
	suite.mockFlowFactory.On("CreateExecutor", ExecutorNameProvisioning, common.ExecutorTypeRegistration,
		[]common.Input{}, []common.Input{}).Return(mockExec)

	suite.executor = newProvisioningExecutor(suite.mockFlowFactory,
		suite.mockGroupService, suite.mockRoleService, suite.mockEntityProvider,
		suite.mockUserSchemaService, suite.mockAuthnProvider)
}

// expectSchemaForProvisioning sets up the user schema service mock for provisioning tests.
// The required-only call returns an empty list (node inputs handle required validation).
// The all-attrs call returns a schema with common provisioning attributes.
func (suite *ProvisioningExecutorTestSuite) expectSchemaForProvisioning() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Maybe()
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "username"},
			{Attribute: "email"},
			{Attribute: "sub"},
		}, nil).Maybe()
}

func (suite *ProvisioningExecutorTestSuite) createMockIdentifyingExecutor() core.ExecutorInterface {
	mockExec := coremock.NewExecutorInterfaceMock(suite.T())
	mockExec.On("GetName").Return(ExecutorNameIdentifying).Maybe()
	mockExec.On("GetType").Return(common.ExecutorTypeUtility).Maybe()
	mockExec.On("GetDefaultInputs").Return([]common.Input{}).Maybe()
	mockExec.On("GetPrerequisites").Return([]common.Input{}).Maybe()
	return mockExec
}

func (suite *ProvisioningExecutorTestSuite) createMockProvisioningExecutor() core.ExecutorInterface {
	mockExec := coremock.NewExecutorInterfaceMock(suite.T())
	mockExec.On("GetName").Return(ExecutorNameProvisioning).Maybe()
	mockExec.On("GetType").Return(common.ExecutorTypeRegistration).Maybe()
	mockExec.On("GetDefaultInputs").Return([]common.Input{}).Maybe()
	mockExec.On("GetPrerequisites").Return([]common.Input{}).Maybe()
	mockExec.On("HasRequiredInputs", mock.Anything, mock.Anything).Return(
		func(ctx *core.NodeContext, execResp *common.ExecutorResponse) bool {
			if len(ctx.NodeInputs) == 0 {
				return true
			}
			for _, input := range ctx.NodeInputs {
				if _, ok := ctx.UserInputs[input.Identifier]; !ok {
					if _, ok := ctx.RuntimeData[input.Identifier]; !ok {
						execResp.Inputs = append(execResp.Inputs, input)
					}
				}
			}
			return len(execResp.Inputs) == 0
		}).Maybe()
	mockExec.On("GetInputs", mock.Anything).Return([]common.Input{}).Maybe()
	mockExec.On("GetRequiredInputs", mock.Anything).Return([]common.Input{}).Maybe()
	return mockExec
}

// makeAuthUserWithRuntimeAttrs creates an AuthUser with runtime attributes for testing.
func makeAuthUserWithRuntimeAttrs(attrs map[string]interface{}) authnprovidermgr.AuthUser {
	type authResultProxy struct {
		RuntimeAttributes map[string]interface{} `json:"runtimeAttributes,omitempty"`
	}
	type authUserProxy struct {
		AuthHistory []authResultProxy `json:"authHistory"`
	}
	raw, _ := json.Marshal(authUserProxy{
		AuthHistory: []authResultProxy{{RuntimeAttributes: attrs}},
	})
	var authUser authnprovidermgr.AuthUser
	_ = json.Unmarshal(raw, &authUser)
	return authUser
}

// makeAuthenticatedAuthUser creates a fully authenticated AuthUser with the given user details.
func makeAuthenticatedAuthUser(userID string) authnprovidermgr.AuthUser {
	type authResultProxy struct {
		IsVerified     bool   `json:"isVerified"`
		LocalUserState string `json:"localUserState"`
	}
	type authUserProxy struct {
		UserID      string            `json:"userId"`
		UserType    string            `json:"userType"`
		OUID        string            `json:"ouId"`
		AuthHistory []authResultProxy `json:"authHistory"`
	}
	raw, _ := json.Marshal(authUserProxy{
		UserID:   userID,
		UserType: testUserType,
		OUID:     testOUID,
		AuthHistory: []authResultProxy{
			{IsVerified: true, LocalUserState: "exists"},
		},
	})
	var authUser authnprovidermgr.AuthUser
	_ = json.Unmarshal(raw, &authUser)
	return authUser
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_NonRegistrationFlow() {
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeAuthentication,
	}

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_Success() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser", "email": "new@example.com"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
			"email":    "new@example.com",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
			{Identifier: "email", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", map[string]interface{}{
		"username": "newuser",
		"email":    "new@example.com",
	}).Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.MatchedBy(func(u *entityprovider.Entity) bool {
		return u.OUID == testOUID && u.Type == testUserType
	}), mock.Anything).Return(createdUser, nil)

	// Mock group assignment
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id",
		mock.MatchedBy(func(members []group.Member) bool {
			return len(members) == 1 &&
				members[0].ID == testNewUserID &&
				members[0].Type == group.MemberTypeUser
		})).Return(nil, nil)

	// Mock role assignment
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id",
		mock.MatchedBy(func(assignments []role.RoleAssignment) bool {
			return len(assignments) == 1 &&
				assignments[0].ID == testNewUserID &&
				assignments[0].Type == role.AssigneeTypeUser
		})).Return(nil)

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.True(suite.T(), resp.AuthUser.IsAuthenticated())
	assert.Equal(suite.T(), testNewUserID, resp.AuthUser.GetUserID())
	suite.mockEntityProvider.AssertExpectations(suite.T())
	suite.mockGroupService.AssertExpectations(suite.T())
	suite.mockRoleService.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_UserAlreadyExists() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "existinguser",
		},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	userID := "user-existing"
	suite.mockEntityProvider.On("IdentifyEntity", map[string]interface{}{
		"username": "existinguser",
	}).Return(&userID, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Contains(suite.T(), resp.FailureReason, "User already exists")
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_NoUserAttributes() {
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{},
		NodeInputs:  []common.Input{},
	}

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CreateUserFails() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	suite.mockEntityProvider.On("IdentifyEntity", mock.Anything).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).
		Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeSystemError, "creation failed", ""))

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Contains(suite.T(), resp.FailureReason, "Failed to create user")
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_AttributesFromAuthUser() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		AuthUser:    makeAuthUserWithRuntimeAttrs(map[string]interface{}{"email": "test@example.com"}),
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "email", Type: "string", Required: true}},
	}

	execResp := &common.ExecutorResponse{
		Inputs:      []common.Input{{Identifier: "email", Type: "string", Required: true}},
		RuntimeData: make(map[string]string),
	}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), result)
	assert.Empty(suite.T(), execResp.Inputs)
}

// TestGetAttributesForProvisioning_SchemaEmpty_ReturnsEmpty verifies that when the schema
// is unavailable (no userTypeKey → getUserType returns ""), an empty map is returned.
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_SchemaEmpty_ReturnsEmpty() {
	ctx := &core.NodeContext{
		UserInputs:  map[string]string{"username": "testuser", "email": "test@example.com"},
		RuntimeData: map[string]string{},
		NodeInputs:  []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Empty(suite.T(), result)
}

// TestGetAttributesForProvisioning_SchemaWhitelist_ExcludesNonSchemaAttrs verifies that the schema
// acts as a whitelist — attributes not in the schema are excluded even if present in context.
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_SchemaWhitelist_ExcludesNonSchemaAttrs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{{Attribute: "username", Required: true}}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"username": "testuser",
			"userID":   "user-123",
			"code":     "auth-code",
			"nonce":    "test-nonce",
		},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "testuser", result["username"])
	assert.NotContains(suite.T(), result, "userID")
	assert.NotContains(suite.T(), result, "code")
	assert.NotContains(suite.T(), result, "nonce")
}

// TestGetAttributesForProvisioning_RequiredAttrsFromMultipleSources verifies that required schema
// attributes are resolved from UserInputs, AuthUser runtime attributes, and RuntimeData.
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_RequiredAttrsFromMultipleSources() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "username", Required: true},
			{Attribute: "email", Required: true},
			{Attribute: "given_name", Required: true},
			{Attribute: "phone", Required: true},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{"username": "testuser"},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email":       "authenticated@example.com",
			"given_name":  "Test",
			"family_name": "User",
		}),
		RuntimeData: map[string]string{userTypeKey: testUserType, "phone": "+1234567890"},
		NodeInputs:  []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "testuser", result["username"])
	assert.Equal(suite.T(), "authenticated@example.com", result["email"])
	assert.Equal(suite.T(), "Test", result["given_name"])
	assert.Equal(suite.T(), "+1234567890", result["phone"])
}

// TestGetAttributesForProvisioning_ContextPriority verifies priority: UserInputs > RuntimeData > AuthUser.
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_ContextPriority() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "name", Required: true},
			{Attribute: "phone", Required: true},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"email": "userinput@example.com",
		},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email": "authenticated@example.com",
			"name":  "Authenticated Name",
		}),
		RuntimeData: map[string]string{
			userTypeKey: testUserType,
			"phone":     "+1234567890",
		},
		NodeInputs: []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	// UserInputs wins for 'email'
	assert.Equal(suite.T(), "userinput@example.com", result["email"])
	// AuthUser provides 'name' (not in UserInputs or RuntimeData)
	assert.Equal(suite.T(), "Authenticated Name", result["name"])
	// RuntimeData provides 'phone' (not in other sources)
	assert.Equal(suite.T(), "+1234567890", result["phone"])
}

// TestGetAttributesForProvisioning_AllAttrsCollectedWhenNoNodeInputs verifies that when
// node inputs are empty, all schema attrs with available values are collected (both required and optional).
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_AllAttrsCollectedWhenNoNodeInputs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "phone", Required: false},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"username": "testuser",
		},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email":      "authenticated@example.com",
			"given_name": "Test",
		}),
		RuntimeData: map[string]string{
			userTypeKey: testUserType,
			"phone":     "+1234567890",
		},
		NodeInputs: []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "authenticated@example.com", result["email"])
	assert.Equal(suite.T(), "+1234567890", result["phone"],
		"optional attr with a value must be collected when node inputs are empty")
}

// TestGetAttributesForProvisioning_OptionalAttrCollectedWhenInNodeInputs verifies that an optional
// schema attr is collected when it is explicitly listed in node inputs.
func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_OptionalAttrCollectedWhenInNodeInputs() {
	nodeInputs := []common.Input{
		{Identifier: "email", Type: "EMAIL_INPUT", Required: true},
		{Identifier: "phone", Type: "TEXT_INPUT", Required: false},
	}
	exec := suite.newExecutorWithNodeInputs(nodeInputs)

	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "phone", Required: false},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"email": "user@example.com",
			"phone": "+1234567890",
		},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  nodeInputs,
	}

	result, _ := exec.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "user@example.com", result["email"])
	assert.Equal(suite.T(), "+1234567890", result["phone"],
		"optional attr in node inputs must be collected")
}

// newExecutorWithNodeInputs creates a provisioningExecutor whose embedded ExecutorInterface
// returns the given inputs from GetRequiredInputs.
func (suite *ProvisioningExecutorTestSuite) newExecutorWithNodeInputs(inputs []common.Input) *provisioningExecutor {
	mockExec := coremock.NewExecutorInterfaceMock(suite.T())
	mockExec.On("GetRequiredInputs", mock.Anything).Return(inputs).Maybe()
	mockExec.On("HasRequiredInputs", mock.Anything, mock.Anything).Return(true).Maybe()

	mockFlowFactory := coremock.NewFlowFactoryInterfaceMock(suite.T())
	mockFlowFactory.On("CreateExecutor", ExecutorNameProvisioning, common.ExecutorTypeRegistration,
		mock.Anything, mock.Anything).Return(mockExec)

	identifyingMock := suite.createMockIdentifyingExecutor()
	mockFlowFactory.On("CreateExecutor", ExecutorNameIdentifying, common.ExecutorTypeUtility,
		mock.Anything, mock.Anything).Return(identifyingMock).Maybe()

	return newProvisioningExecutor(mockFlowFactory,
		suite.mockGroupService, suite.mockRoleService, suite.mockEntityProvider,
		suite.mockUserSchemaService, suite.mockAuthnProvider)
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_FilteredPath_RequiredAttrFromUserInputs() {
	nodeInputs := []common.Input{
		{Identifier: "username", Type: "TEXT_INPUT", Required: true},
		{Identifier: "email", Type: "EMAIL_INPUT", Required: true},
	}
	exec := suite.newExecutorWithNodeInputs(nodeInputs)

	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "username", Required: true},
			{Attribute: "email", Required: true},
			{Attribute: "mobileNumber", Required: true},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"email":    "userinput@example.com",
			"username": "inputuser",
		},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  nodeInputs,
	}

	result, _ := exec.getAttributesForProvisioning(ctx)

	// Both required attrs should be included regardless of nodeInputSet
	assert.Equal(suite.T(), "userinput@example.com", result["email"])
	assert.Equal(suite.T(), "inputuser", result["username"])
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_FilteredPath_UserInputTakesPriority() {
	nodeInputs := []common.Input{
		{Identifier: "email", Type: "EMAIL_INPUT", Required: true},
	}
	exec := suite.newExecutorWithNodeInputs(nodeInputs)

	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "username", Required: true},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{"email": "userinput@example.com"},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email":    "authenticated@example.com",
			"username": "federateduser",
		}),
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  nodeInputs,
	}

	result, _ := exec.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "userinput@example.com", result["email"],
		"UserInputs must win over AuthUser for the same key")
	assert.Equal(suite.T(), "federateduser", result["username"],
		"required schema attr from AuthUser must still be included when not in UserInputs")
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_SkipProvisioning_UserAlreadyExists() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "existinguser",
		},
		RuntimeData: map[string]string{
			common.RuntimeKeySkipProvisioning: dataValueTrue,
			userTypeKey:                       testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
	}

	userID := "existing-user-123"
	attrs := map[string]interface{}{
		"username": "existinguser",
	}
	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&userID, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), "existing-user-123", resp.RuntimeData[userAttributeUserID])
	// Verify that CreateUser was not called (provisioning was skipped)
	// Verify that CreateUser was not called (provisioning was skipped)
	suite.mockEntityProvider.AssertExpectations(suite.T())
	suite.mockEntityProvider.AssertNotCalled(suite.T(), "CreateEntity")
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_SkipProvisioning_ProceedsNormally() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
			"email":    "new@example.com",
		},
		RuntimeData: map[string]string{
			common.RuntimeKeySkipProvisioning: "false",
			ouIDKey:                           testOUID,
			userTypeKey:                       testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
			{Identifier: "email", Type: "string", Required: true},
		},
		// No NodeProperties - should skip group/role assignment
	}

	attrs := map[string]interface{}{
		"username": "newuser",
		"email":    "new@example.com",
	}
	attrsJSON, _ := json.Marshal(attrs)

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
	suite.mockEntityProvider.On("CreateEntity", mock.MatchedBy(func(u *entityprovider.Entity) bool {
		return u.OUID == testOUID && u.Type == testUserType
	}), mock.Anything).Return(createdUser, nil)

	// No group/role assignment mocks - assignments should be skipped

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.True(suite.T(), resp.AuthUser.IsAuthenticated())
	assert.Equal(suite.T(), testNewUserID, resp.AuthUser.GetUserID())
	// userAutoProvisioned flag is not set in registration flows
	assert.Equal(suite.T(), testNewUserID, resp.AuthUser.GetUserID())
	suite.mockEntityProvider.AssertExpectations(suite.T())

	// Verify no group/role methods were called
	suite.mockGroupService.AssertNotCalled(suite.T(), "GetGroup")
	suite.mockRoleService.AssertNotCalled(suite.T(), "AddAssignments")
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_UserEligibleForProvisioning() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeAuthentication,
		UserInputs: map[string]string{
			"username": "provisioneduser",
			"email":    "provisioned@example.com",
		},
		RuntimeData: map[string]string{
			common.RuntimeKeyUserEligibleForProvisioning: dataValueTrue,
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
			{Identifier: "email", Type: "string", Required: true},
		},
	}

	attrs := map[string]interface{}{
		"username": "provisioneduser",
		"email":    "provisioned@example.com",
	}
	attrsJSON, _ := json.Marshal(attrs)

	createdUser := &entityprovider.Entity{
		ID:         "user-provisioned",
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
	suite.mockEntityProvider.On("CreateEntity", mock.MatchedBy(func(u *entityprovider.Entity) bool {
		return u.OUID == testOUID && u.Type == testUserType
	}), mock.Anything).Return(createdUser, nil)

	authenticatedUser := makeAuthenticatedAuthUser("user-provisioned")
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.True(suite.T(), resp.AuthUser.IsAuthenticated())
	assert.Equal(suite.T(), "user-provisioned", resp.AuthUser.GetUserID())
	assert.Equal(suite.T(), dataValueTrue, resp.RuntimeData[common.RuntimeKeyUserAutoProvisioned])
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_UserAutoProvisionedFlag_SetAfterCreation() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser", "email": "new@example.com"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeAuthentication,
		UserInputs: map[string]string{
			"username": "newuser",
			"email":    "new@example.com",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
			common.RuntimeKeyUserEligibleForProvisioning: dataValueTrue,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
			{Identifier: "email", Type: "string", Required: true},
		},
	}

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), dataValueTrue, resp.RuntimeData[common.RuntimeKeyUserAutoProvisioned],
		"userAutoProvisioned flag should be set to true after successful provisioning")
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestAppendNonIdentifyingAttributes() {
	tests := []struct {
		name               string
		userInputs         map[string]string
		runtimeData        map[string]string
		expectedPassword   string
		shouldHavePassword bool
	}{
		{
			name: "PasswordInUserInput",
			userInputs: map[string]string{
				"username": "testuser",
				"password": "secure123",
			},
			runtimeData:        map[string]string{},
			expectedPassword:   "secure123",
			shouldHavePassword: true,
		},
		{
			name: "PasswordInRuntimeData",
			userInputs: map[string]string{
				"username": "testuser",
			},
			runtimeData: map[string]string{
				"password": "runtime-password",
			},
			expectedPassword:   "runtime-password",
			shouldHavePassword: true,
		},
		{
			name: "NoPassword",
			userInputs: map[string]string{
				"username": "testuser",
			},
			runtimeData:        map[string]string{},
			shouldHavePassword: false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			ctx := &core.NodeContext{
				UserInputs:  tt.userInputs,
				RuntimeData: tt.runtimeData,
			}

			attributes := map[string]interface{}{
				"username": "testuser",
			}

			suite.executor.appendNonIdentifyingAttributes(ctx, &attributes)

			if tt.shouldHavePassword {
				assert.Contains(suite.T(), attributes, "password")
				assert.Equal(suite.T(), tt.expectedPassword, attributes["password"])
			} else {
				assert.NotContains(suite.T(), attributes, "password")
				assert.Equal(suite.T(), 1, len(attributes)) // Only username
			}
		})
	}
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_RegistrationFlow_SkipProvisioningWithExistingUser() {
	suite.expectSchemaForProvisioning()
	userID := "existing-user-id"
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "existinguser",
		},
		RuntimeData: map[string]string{
			common.RuntimeKeySkipProvisioning: dataValueTrue,
			userTypeKey:                       testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
	}

	attrs := map[string]interface{}{
		"username": "existinguser",
	}
	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&userID, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), userID, resp.RuntimeData[userAttributeUserID])
	assert.Empty(suite.T(), resp.FailureReason)
	suite.mockEntityProvider.AssertNotCalled(suite.T(), "CreateEntity")
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_MissingInputs_MissingOUID() {
	suite.expectSchemaForProvisioning()
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{"username": "newuser"},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	suite.mockEntityProvider.On("IdentifyEntity", map[string]interface{}{"username": "newuser"}).
		Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "Failed to create user", resp.FailureReason)
	suite.mockEntityProvider.AssertNotCalled(suite.T(), "CreateEntity")
	suite.mockEntityProvider.AssertExpectations(suite.T())
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_MissingInputs_MissingUserType() {
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{"username": "newuser"},
		RuntimeData: map[string]string{ouIDKey: testOUID},
		NodeInputs:  []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	suite.mockEntityProvider.AssertNotCalled(suite.T(), "IdentifyEntity")
	suite.mockEntityProvider.AssertNotCalled(suite.T(), "CreateEntity")
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CreateUserFailures() {
	suite.expectSchemaForProvisioning()
	tests := []struct {
		name               string
		createdUser        *entityprovider.Entity
		createUserError    *entityprovider.EntityProviderError
		expectedFailReason string
	}{
		{
			name:        "ServiceReturnsError",
			createdUser: nil,
			createUserError: entityprovider.NewEntityProviderError(
				entityprovider.ErrorCodeSystemError, "Database error", ""),
			expectedFailReason: "Failed to create user",
		},
		{
			name:               "CreatedUserIsNil",
			createdUser:        nil,
			createUserError:    nil,
			expectedFailReason: "Something went wrong while creating the user",
		},
		{
			name: "CreatedUserHasEmptyID",
			createdUser: &entityprovider.Entity{
				ID:         "",
				OUID:       testOUID,
				Type:       testUserType,
				Attributes: []byte(`{"username":"newuser"}`),
			},
			createUserError:    nil,
			expectedFailReason: "Something went wrong while creating the user",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Clear expectations before each test
			suite.mockEntityProvider.ExpectedCalls = nil

			ctx := &core.NodeContext{
				ExecutionID: "flow-123",
				FlowType:    common.FlowTypeRegistration,
				UserInputs: map[string]string{
					"username": "newuser",
				},
				RuntimeData: map[string]string{
					ouIDKey:     testOUID,
					userTypeKey: testUserType,
				},
				NodeInputs: []common.Input{
					{Identifier: "username", Type: "string", Required: true},
				},
			}

			attrs := map[string]interface{}{
				"username": "newuser",
			}
			suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
				entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
			suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).
				Return(tt.createdUser, tt.createUserError)

			resp, err := suite.executor.Execute(ctx)

			assert.NoError(suite.T(), err)
			assert.NotNil(suite.T(), resp)
			assert.Equal(suite.T(), common.ExecFailure, resp.Status)
			assert.Equal(suite.T(), tt.expectedFailReason, resp.FailureReason)
			suite.mockEntityProvider.AssertExpectations(suite.T())
		})
	}
}

func (suite *ProvisioningExecutorTestSuite) TestGetOUID() {
	tests := []struct {
		name        string
		runtimeData map[string]string
		userInputs  map[string]string
		expected    string
	}{
		{
			name: "RuntimeOUIDTakesPriority",
			runtimeData: map[string]string{
				ouIDKey:        "ou-from-resolver",
				defaultOUIDKey: "ou-from-usertype",
			},
			userInputs: map[string]string{
				ouIDKey: "ou-from-userinput",
			},
			expected: "ou-from-resolver",
		},
		{
			name: "DefaultOUIDWhenNoExplicitOUID",
			runtimeData: map[string]string{
				defaultOUIDKey: "ou-from-usertype",
			},
			expected: "ou-from-usertype",
		},
		{
			name:        "ReturnsEmptyWhenNotFound",
			runtimeData: map[string]string{},
			expected:    "",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			ctx := &core.NodeContext{
				RuntimeData: tt.runtimeData,
				UserInputs:  tt.userInputs,
			}

			ouID := suite.executor.getOUID(ctx)

			assert.Equal(suite.T(), tt.expected, ouID)
		})
	}
}

func (suite *ProvisioningExecutorTestSuite) TestGetUserType() {
	tests := []struct {
		name        string
		runtimeData map[string]string
		expected    string
	}{
		{
			name: "Found",
			runtimeData: map[string]string{
				userTypeKey: "CUSTOM_USER_TYPE",
			},
			expected: "CUSTOM_USER_TYPE",
		},
		{
			name:        "NotFound",
			runtimeData: map[string]string{},
			expected:    "",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			ctx := &core.NodeContext{
				RuntimeData: tt.runtimeData,
			}

			userType := suite.executor.getUserType(ctx)

			assert.Equal(suite.T(), tt.expected, userType)
		})
	}
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_AllAttributesInRuntimeData() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{
			"email":     "user@example.com",
			"username":  "testuser",
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "email", Type: "string", Required: true},
			{Identifier: "username", Type: "string", Required: true},
		},
	}

	execResp := &common.ExecutorResponse{
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}

	inputRequired := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), inputRequired)
	assert.Equal(suite.T(), 0, len(execResp.Inputs))
}

// Test group assignment failure - provisioning should fail, but role assignment should still be attempted
func (suite *ProvisioningExecutorTestSuite) TestExecute_Failure_GroupAssignmentFails() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	// Mock group assignment fails (e.g., group doesn't exist)
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id", mock.Anything).
		Return(nil, &serviceerror.ServiceError{
			Error: i18ncore.I18nMessage{Key: "error.test.group_not_found", DefaultValue: "Group not found"},
		})

	// Role assignment should still be attempted
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id", mock.Anything).Return(nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Contains(suite.T(), resp.FailureReason, "Failed to assign groups and roles")
	assert.Contains(suite.T(), resp.FailureReason, "group")

	// Verify role assignment WAS attempted despite group failure
	suite.mockRoleService.AssertExpectations(suite.T())
}

// Test both group and role assignment failure - provisioning should fail with combined error
func (suite *ProvisioningExecutorTestSuite) TestExecute_Failure_BothGroupAndRoleAssignmentFail() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	// Mock group assignment fails
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id", mock.Anything).
		Return(nil, &serviceerror.ServiceError{
			Error: i18ncore.I18nMessage{Key: "error.test.group_not_found", DefaultValue: "Group not found"},
		})

	// Mock role assignment also fails
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id", mock.Anything).
		Return(&serviceerror.ServiceError{
			Error: i18ncore.I18nMessage{Key: "error.test.role_not_found", DefaultValue: "Role not found"},
		})

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "Failed to assign groups and roles", resp.FailureReason)

	// Verify both services were called (new behavior: try both even if one fails)
	suite.mockGroupService.AssertExpectations(suite.T())
	suite.mockRoleService.AssertExpectations(suite.T())
}

// Test role assignment failure - provisioning should fail, but group assignment succeeds
func (suite *ProvisioningExecutorTestSuite) TestExecute_Failure_RoleAssignmentFails() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	// Group assignment succeeds
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id", mock.Anything).
		Return(nil, nil)

	// Role assignment fails (e.g., role doesn't exist)
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id", mock.Anything).
		Return(&serviceerror.ServiceError{
			Error: i18ncore.I18nMessage{Key: "error.test.role_not_found", DefaultValue: "Role not found"},
		})

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Contains(suite.T(), resp.FailureReason, "Failed to assign groups and roles")
	assert.Contains(suite.T(), resp.FailureReason, "role")

	// Verify both group and role services were called
	suite.mockGroupService.AssertExpectations(suite.T())
	suite.mockRoleService.AssertExpectations(suite.T())
}

// Test group with existing members - user should be appended
func (suite *ProvisioningExecutorTestSuite) TestExecute_GroupWithExistingMembers() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	// Mock group assignment - AddGroupMembers only adds the new user, not existing members
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id",
		mock.MatchedBy(func(members []group.Member) bool {
			return len(members) == 1 &&
				members[0].ID == testNewUserID &&
				members[0].Type == group.MemberTypeUser
		})).Return(nil, nil)

	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id", mock.Anything).Return(nil)

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	suite.mockGroupService.AssertExpectations(suite.T())
}

// Test authentication flow with auto-provisioning still assigns groups/roles
func (suite *ProvisioningExecutorTestSuite) TestExecute_AuthFlow_AutoProvisioning_AssignsGroupsAndRoles() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "provisioneduser"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeAuthentication,
		UserInputs: map[string]string{
			"username": "provisioneduser",
		},
		RuntimeData: map[string]string{
			common.RuntimeKeyUserEligibleForProvisioning: dataValueTrue,
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         "user-provisioned",
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).Return(createdUser, nil)

	// Mock successful group and role assignment
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id", mock.Anything).
		Return(nil, nil)
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id", mock.Anything).Return(nil)

	authenticatedUser := makeAuthenticatedAuthUser("user-provisioned")
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), dataValueTrue, resp.RuntimeData[common.RuntimeKeyUserAutoProvisioned])

	// Verify assignments were made
	suite.mockGroupService.AssertExpectations(suite.T())
	suite.mockRoleService.AssertExpectations(suite.T())
}

// Test successful provisioning with both group and role assignment (detailed verification)
func (suite *ProvisioningExecutorTestSuite) TestExecute_Success_WithGroupAndRoleAssignment() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"username": "newuser", "email": "new@example.com"}
	attrsJSON, _ := json.Marshal(attrs)

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"username": "newuser",
			"email":    "new@example.com",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{
			{Identifier: "username", Type: "string", Required: true},
			{Identifier: "email", Type: "string", Required: true},
		},
		NodeProperties: map[string]interface{}{
			"assignGroup": "test-group-id",
			"assignRole":  "test-role-id",
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", map[string]interface{}{
		"username": "newuser",
		"email":    "new@example.com",
	}).Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		OUID:       testOUID,
		Type:       testUserType,
		Attributes: attrsJSON,
	}

	suite.mockEntityProvider.On("CreateEntity", mock.MatchedBy(func(u *entityprovider.Entity) bool {
		return u.OUID == testOUID && u.Type == testUserType
	}), mock.Anything).Return(createdUser, nil)

	// Mock group assignment
	suite.mockGroupService.On("AddGroupMembers", mock.Anything, "test-group-id",
		mock.MatchedBy(func(members []group.Member) bool {
			return len(members) == 1 &&
				members[0].ID == testNewUserID &&
				members[0].Type == group.MemberTypeUser
		})).Return(nil, nil)

	// Mock role assignment
	suite.mockRoleService.On("AddAssignments", mock.Anything, "test-role-id",
		mock.MatchedBy(func(assignments []role.RoleAssignment) bool {
			return len(assignments) == 1 &&
				assignments[0].ID == testNewUserID &&
				assignments[0].Type == role.AssigneeTypeUser
		})).Return(nil)

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), testNewUserID, resp.AuthUser.GetUserID())

	// Verify all mocks were called
	suite.mockEntityProvider.AssertExpectations(suite.T())
	suite.mockGroupService.AssertExpectations(suite.T())
	suite.mockRoleService.AssertExpectations(suite.T())
}

// Cross-OU provisioning tests

func (suite *ProvisioningExecutorTestSuite) TestExecute_CrossOU_Success() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"sub": "user-sub-123"}
	attrsJSON, _ := json.Marshal(attrs)

	existingUserID := testExistingUserID
	existingUser := &entityprovider.Entity{
		ID:   existingUserID,
		OUID: "ou-source",
	}

	createdUser := &entityprovider.Entity{
		ID:         testNewUserID,
		Type:       testUserType,
		OUID:       testOUID,
		Attributes: attrsJSON,
	}

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"sub": "user-sub-123",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeProperties: map[string]interface{}{
			common.NodePropertyAllowCrossOUProvisioning: true,
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&existingUserID, nil)
	suite.mockEntityProvider.On("GetEntity", existingUserID).Return(existingUser, nil)
	suite.mockEntityProvider.On("CreateEntity", mock.MatchedBy(func(u *entityprovider.Entity) bool {
		return u.OUID == testOUID
	}), mock.Anything).Return(createdUser, nil)

	authenticatedUser := makeAuthenticatedAuthUser(testNewUserID)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, createdUser, mock.Anything).
		Return(authenticatedUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecComplete, resp.Status)
	assert.Equal(suite.T(), testNewUserID, resp.RuntimeData[userAttributeUserID])
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CrossOU_NotEnabled_Fails() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"sub": "user-sub-123"}

	existingUserID := testExistingUserID

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"sub": "user-sub-123",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeProperties: map[string]interface{}{},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&existingUserID, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "User already exists", resp.FailureReason)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CrossOU_SameOU_Fails() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"sub": "user-sub-123"}

	existingUserID := testExistingUserID
	existingUser := &entityprovider.Entity{
		ID:   existingUserID,
		OUID: testOUID, // same as target
	}

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"sub": "user-sub-123",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeProperties: map[string]interface{}{
			common.NodePropertyAllowCrossOUProvisioning: true,
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&existingUserID, nil)
	suite.mockEntityProvider.On("GetEntity", existingUserID).Return(existingUser, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "User already exists in the target organization", resp.FailureReason)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CrossOU_NoTargetOU_Fails() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"sub": "user-sub-123"}

	existingUserID := testExistingUserID

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"sub": "user-sub-123",
		},
		RuntimeData: map[string]string{
			userTypeKey: testUserType,
			// no ouIDKey — target OU not set
		},
		NodeProperties: map[string]interface{}{
			common.NodePropertyAllowCrossOUProvisioning: true,
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&existingUserID, nil)

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "Target OU is not set for cross-OU provisioning", resp.FailureReason)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_CrossOU_GetUserError() {
	suite.expectSchemaForProvisioning()
	attrs := map[string]interface{}{"sub": "user-sub-123"}

	existingUserID := testExistingUserID

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs: map[string]string{
			"sub": "user-sub-123",
		},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeProperties: map[string]interface{}{
			common.NodePropertyAllowCrossOUProvisioning: true,
		},
	}

	suite.mockEntityProvider.On("IdentifyEntity", attrs).Return(&existingUserID, nil)
	suite.mockEntityProvider.On("GetEntity", existingUserID).Return(nil,
		entityprovider.NewEntityProviderError(entityprovider.ErrorCodeSystemError, "db error", ""))

	resp, err := suite.executor.Execute(ctx)

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), resp)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaAttrSatisfiedByUserInputs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{{Attribute: "email", DisplayName: "Email"}}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{"email": "user@example.com"},
		RuntimeData: map[string]string{userTypeKey: testUserType},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), result)
	assert.Empty(suite.T(), execResp.Inputs)
	assert.Nil(suite.T(), execResp.ForwardedData)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaAttrSatisfiedByRuntimeData() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{{Attribute: "email", DisplayName: ""}}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType, "email": "user@example.com"},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), result)
	assert.Empty(suite.T(), execResp.Inputs)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaAttrSatisfiedByAuthnAttrs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", DisplayName: "Email"},
			{Attribute: "firstName", DisplayName: "First Name"},
		}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email":     "user@example.com",
			"firstName": "Test",
		}),
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), result)
	assert.Empty(suite.T(), execResp.Inputs)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaAttrMissing_AppendedToInputsAndForwardedData() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", DisplayName: "Email Address"},
			{Attribute: "firstName", DisplayName: ""},
		}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.False(suite.T(), result)
	assert.Len(suite.T(), execResp.Inputs, 2)

	inputMap := make(map[string]common.Input, len(execResp.Inputs))
	for _, inp := range execResp.Inputs {
		inputMap[inp.Identifier] = inp
	}

	emailInput, ok := inputMap["email"]
	assert.True(suite.T(), ok)
	assert.True(suite.T(), emailInput.Required)
	assert.Equal(suite.T(), "Email Address", emailInput.DisplayName)

	firstNameInput, ok := inputMap["firstName"]
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "", firstNameInput.DisplayName)

	assert.NotNil(suite.T(), execResp.ForwardedData)
	fwdInputs, ok := execResp.ForwardedData[common.ForwardedDataKeyInputs].([]common.Input)
	assert.True(suite.T(), ok)
	assert.Len(suite.T(), fwdInputs, 2)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaAttrCoveredByNodeInput_NotDuplicated() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{{Attribute: "email", DisplayName: "Email"}}, nil).Once()

	// email is already a node-defined input — schema must not create a second copy
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "email", Type: "string", Required: true}},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.False(suite.T(), result, "node input still missing so overall result is false")
	emailCount := 0
	for _, inp := range execResp.Inputs {
		if inp.Identifier == "email" {
			emailCount++
		}
	}
	assert.Equal(suite.T(), 1, emailCount, "email must appear exactly once, not duplicated by schema")
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_MissingNodeInput_SchemaAttrsSatisfied_ReturnsFalse() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{{Attribute: "email", DisplayName: ""}}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{"email": "user@example.com"},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "username", Required: true}},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.False(suite.T(), result, "node input username is missing so overall must be false")
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_SchemaServiceError_FallsThrough() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return(nil, &serviceerror.ServiceError{Code: "internal_error"}).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.True(suite.T(), result, "schema service error should not fail the executor")
	assert.Empty(suite.T(), execResp.Inputs)
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_SchemaFilteredNoNodeInputs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "username", Required: true},
			{Attribute: "email", Required: true},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs: map[string]string{
			"username":    "testuser",
			"extra_field": "should-not-appear",
		},
		AuthUser: makeAuthUserWithRuntimeAttrs(map[string]interface{}{
			"email": "test@example.com",
		}),
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "testuser", result["username"])
	assert.Equal(suite.T(), "test@example.com", result["email"])
	assert.NotContains(suite.T(), result, "extra_field",
		"attrs not defined in schema must be excluded when schema is available")
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_OptionalAttrCollectedWhenNoNodeInputs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "phone", Required: false},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs:  map[string]string{"email": "user@example.com"},
		RuntimeData: map[string]string{userTypeKey: testUserType, "phone": "+1234567890"},
		NodeInputs:  []common.Input{},
	}

	result, _ := suite.executor.getAttributesForProvisioning(ctx)

	assert.Equal(suite.T(), "user@example.com", result["email"])
	assert.Equal(suite.T(), "+1234567890", result["phone"],
		"optional schema attr with a value must be collected when node inputs are empty")
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_SchemaServiceError_ReturnsError() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return(nil, &serviceerror.ServiceError{Code: "internal_error"}).Once()

	ctx := &core.NodeContext{
		UserInputs:  map[string]string{"email": "user@example.com", "username": "testuser"},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}

	result, err := suite.executor.getAttributesForProvisioning(ctx)

	assert.Nil(suite.T(), result, "schema service error must return nil map")
	assert.Error(suite.T(), err, "schema service error must propagate as an error")
}

func (suite *ProvisioningExecutorTestSuite) TestGetAttributesForProvisioning_OptionalAttrSkippedWhenNotInNodeInputs() {
	nodeInputs := []common.Input{{Identifier: "email", Required: true}}
	exec := suite.newExecutorWithNodeInputs(nodeInputs)

	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{
			{Attribute: "email", Required: true},
			{Attribute: "phone", Required: false},
		}, nil).Once()

	ctx := &core.NodeContext{
		UserInputs:  map[string]string{"email": "user@example.com", "phone": "+1234567890"},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  nodeInputs,
	}

	result, err := exec.getAttributesForProvisioning(ctx)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "user@example.com", result["email"])
	assert.NotContains(suite.T(), result, "phone",
		"optional attr not in nodeInputSet must be skipped when nodeInputSet is non-empty")
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_MissingNodeInputs_ExecUserInputRequired() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecUserInputRequired, resp.Status)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_GetAttributesError_ReturnsServerError() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return(nil, &serviceerror.ServiceError{Code: "internal_error"}).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}

	resp, err := suite.executor.Execute(ctx)

	assert.Nil(suite.T(), resp)
	assert.Error(suite.T(), err)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_EmptySchemaAttrs_NoUserAttributes() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, false).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.Equal(suite.T(), "No user attributes provided for provisioning", resp.FailureReason)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_IdentifyUser_AmbiguousMatch_ReturnsFailureEarly() {
	suite.expectSchemaForProvisioning()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{"username": "newuser"},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	suite.mockEntityProvider.On("IdentifyEntity",
		map[string]interface{}{"username": "newuser"}).
		Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeAmbiguousEntity, "ambiguous", ""))

	resp, err := suite.executor.Execute(ctx)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), resp)
	assert.Equal(suite.T(), common.ExecFailure, resp.Status)
	assert.NotEqual(suite.T(), failureReasonUserNotFound, resp.FailureReason)
}

func (suite *ProvisioningExecutorTestSuite) TestExecute_UnmarshalAttributesError_ReturnsServerError() {
	suite.expectSchemaForProvisioning()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		FlowType:    common.FlowTypeRegistration,
		UserInputs:  map[string]string{"username": "newuser"},
		RuntimeData: map[string]string{
			ouIDKey:     testOUID,
			userTypeKey: testUserType,
		},
		NodeInputs: []common.Input{{Identifier: "username", Type: "string", Required: true}},
	}

	suite.mockEntityProvider.On("IdentifyEntity", map[string]interface{}{"username": "newuser"}).
		Return(nil, entityprovider.NewEntityProviderError(entityprovider.ErrorCodeEntityNotFound, "", ""))
	suite.mockEntityProvider.On("CreateEntity", mock.Anything, mock.Anything).
		Return(&entityprovider.Entity{
			ID:         testNewUserID,
			OUID:       testOUID,
			Type:       testUserType,
			Attributes: []byte(`invalid json`),
		}, nil)
	suite.mockAuthnProvider.On("AuthenticateResolvedUser", mock.Anything, mock.Anything, mock.Anything).
		Return(authnprovidermgr.AuthUser{}, &serviceerror.ServiceError{})

	resp, err := suite.executor.Execute(ctx)

	assert.Nil(suite.T(), resp)
	assert.Error(suite.T(), err)
}

func (suite *ProvisioningExecutorTestSuite) TestHasRequiredInputs_NilRuntimeData_IsInitialized() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs:  []common.Input{},
	}
	execResp := &common.ExecutorResponse{RuntimeData: nil}

	suite.executor.HasRequiredInputs(ctx, execResp)

	assert.NotNil(suite.T(), execResp.RuntimeData)
}

func (suite *ProvisioningExecutorTestSuite) TestCheckNodeInputs_InputNotSatisfiedByAuthnAttrs() {
	suite.mockUserSchemaService.On("GetNonCredentialAttributes", mock.Anything, testUserType, true).
		Return([]userschema.AttributeInfo{}, nil).Once()

	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		UserInputs:  map[string]string{},
		RuntimeData: map[string]string{userTypeKey: testUserType},
		NodeInputs: []common.Input{{Identifier: "username", Required: true}},
		AuthUser:   makeAuthUserWithRuntimeAttrs(map[string]interface{}{"email": "test@example.com"}),
	}
	execResp := &common.ExecutorResponse{RuntimeData: make(map[string]string)}

	result := suite.executor.HasRequiredInputs(ctx, execResp)

	assert.False(suite.T(), result)
	assert.Len(suite.T(), execResp.Inputs, 1)
	assert.Equal(suite.T(), "username", execResp.Inputs[0].Identifier)
}

func (suite *ProvisioningExecutorTestSuite) TestGetGroupToAssign_NonStringValue_ReturnsEmpty() {
	ctx := &core.NodeContext{
		NodeProperties: map[string]interface{}{
			propertyKeyAssignGroup: 42,
		},
	}

	result := suite.executor.getGroupToAssign(ctx)

	assert.Equal(suite.T(), "", result)
}

func (suite *ProvisioningExecutorTestSuite) TestGetRoleToAssign_NonStringValue_ReturnsEmpty() {
	ctx := &core.NodeContext{
		NodeProperties: map[string]interface{}{
			propertyKeyAssignRole: true,
		},
	}

	result := suite.executor.getRoleToAssign(ctx)

	assert.Equal(suite.T(), "", result)
}

func (suite *ProvisioningExecutorTestSuite) TestFetchSchemaAttributes_NilService_ReturnsNil() {
	pe := &provisioningExecutor{
		ExecutorInterface:            suite.executor.ExecutorInterface,
		identifyingExecutorInterface: suite.executor.identifyingExecutorInterface,
		entityProvider:               suite.executor.entityProvider,
		groupService:                 suite.executor.groupService,
		roleService:                  suite.executor.roleService,
		userSchemaService:            nil,
		logger:                       suite.executor.logger,
	}

	ctx := &core.NodeContext{
		RuntimeData: map[string]string{userTypeKey: testUserType},
	}

	attrs, err := pe.fetchSchemaAttributes(ctx, pe.logger)

	assert.NoError(suite.T(), err)
	assert.Nil(suite.T(), attrs)
}

func (suite *ProvisioningExecutorTestSuite) TestFetchAllNonCredentialAttributes_NilService_ReturnsNil() {
	pe := &provisioningExecutor{
		ExecutorInterface:            suite.executor.ExecutorInterface,
		identifyingExecutorInterface: suite.executor.identifyingExecutorInterface,
		entityProvider:               suite.executor.entityProvider,
		groupService:                 suite.executor.groupService,
		roleService:                  suite.executor.roleService,
		userSchemaService:            nil,
		logger:                       suite.executor.logger,
	}

	ctx := &core.NodeContext{
		RuntimeData: map[string]string{userTypeKey: testUserType},
	}

	attrs, err := pe.fetchAllNonCredentialAttributes(ctx)

	assert.NoError(suite.T(), err)
	assert.Nil(suite.T(), attrs)
}

func (suite *ProvisioningExecutorTestSuite) TestCreateUserInStore_MissingUserType_ReturnsError() {
	ctx := &core.NodeContext{
		ExecutionID: "flow-123",
		RuntimeData: map[string]string{ouIDKey: testOUID},
	}

	result, err := suite.executor.createUserInStore(ctx, map[string]interface{}{"username": "testuser"})

	assert.Nil(suite.T(), result)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "user type not found")
}
