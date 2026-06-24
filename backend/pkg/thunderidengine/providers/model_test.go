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

package providers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

type ModelTestSuite struct {
	suite.Suite
}

func TestModelSuite(t *testing.T) {
	suite.Run(t, new(ModelTestSuite))
}

// AuthUser tests live in auth_user_test.go — the multi-provider AuthUser API
// (ProviderNames / StateFor / SetStateFor) is exercised there.

// ----- NodeDefinition YAML -----

func (suite *ModelTestSuite) TestNodeDefinition_MarshalYAML_NoMeta() {
	nd := NodeDefinition{ID: "start", Type: "START"}
	out, err := yaml.Marshal(&nd)
	suite.Require().NoError(err)
	assert.Contains(suite.T(), string(out), "start")
}

func (suite *ModelTestSuite) TestNodeDefinition_YAML_RoundTrip_WithMeta() {
	meta := map[string]interface{}{"key": "value", "count": float64(3)}
	nd := NodeDefinition{ID: "node1", Type: "PROMPT", Meta: meta}

	out, err := yaml.Marshal(&nd)
	suite.Require().NoError(err)

	var restored NodeDefinition
	suite.Require().NoError(yaml.Unmarshal(out, &restored))

	assert.Equal(suite.T(), nd.ID, restored.ID)
	assert.Equal(suite.T(), nd.Type, restored.Type)
	restoredMeta, ok := restored.Meta.(map[string]interface{})
	suite.Require().True(ok)
	assert.Equal(suite.T(), "value", restoredMeta["key"])
}

func (suite *ModelTestSuite) TestNodeDefinition_UnmarshalYAML_InvalidMetaJSON() {
	raw := `id: node1
type: PROMPT
meta: "not-valid-json{{"`
	var nd NodeDefinition
	suite.Require().NoError(yaml.Unmarshal([]byte(raw), &nd))
	assert.Equal(suite.T(), "node1", nd.ID)
}

// ----- GetDuration -----

func (suite *ModelTestSuite) TestNodeExecutionRecord_GetDuration() {
	suite.T().Run("zero times returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), (&NodeExecutionRecord{}).GetDuration())
	})

	suite.T().Run("only start time returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), (&NodeExecutionRecord{StartTime: 1000}).GetDuration())
	})

	suite.T().Run("calculates duration in ms", func(t *testing.T) {
		r := &NodeExecutionRecord{StartTime: 1000, EndTime: 1002}
		assert.Equal(t, int64(2000), r.GetDuration())
	})
}

func (suite *ModelTestSuite) TestExecutionAttempt_GetDuration() {
	suite.T().Run("zero times returns 0", func(t *testing.T) {
		assert.Equal(t, int64(0), (&ExecutionAttempt{}).GetDuration())
	})

	suite.T().Run("calculates duration in ms", func(t *testing.T) {
		e := &ExecutionAttempt{StartTime: 500, EndTime: 503}
		assert.Equal(t, int64(3000), e.GetDuration())
	})
}

// ----- Input.IsSensitive -----

func (suite *ModelTestSuite) TestInput_IsSensitive() {
	sensitive := []string{InputTypePassword, InputTypeOTP}
	for _, typ := range sensitive {
		assert.True(suite.T(), Input{Type: typ}.IsSensitive(), "expected %q to be sensitive", typ)
	}

	notSensitive := []string{InputTypeText, InputTypeEmail, InputTypePhone, InputTypeHidden, InputTypeSelect}
	for _, typ := range notSensitive {
		assert.False(suite.T(), Input{Type: typ}.IsSensitive(), "expected %q to not be sensitive", typ)
	}
}

// ----- Event -----

func (suite *ModelTestSuite) TestEvent_WithStatus() {
	evt := &Event{}
	assert.Same(suite.T(), evt, evt.WithStatus("success"))
	assert.Equal(suite.T(), "success", evt.Status)
}

func (suite *ModelTestSuite) TestEvent_WithData() {
	evt := &Event{}
	assert.Same(suite.T(), evt, evt.WithData("user_id", "u-1"))
	assert.Equal(suite.T(), "u-1", evt.Data["user_id"])

	evt.WithData("client_id", "c-1")
	assert.Equal(suite.T(), "c-1", evt.Data["client_id"])
}

func (suite *ModelTestSuite) TestEvent_WithDataMap() {
	evt := &Event{Data: map[string]interface{}{"existing": true}}
	evt.WithDataMap(map[string]interface{}{
		"user_id":  "u-1",
		"existing": false,
	})
	assert.Equal(suite.T(), false, evt.Data["existing"])
	assert.Equal(suite.T(), "u-1", evt.Data["user_id"])
}

func (suite *ModelTestSuite) TestEvent_Validate() {
	now := time.Now()

	suite.T().Run("nil event fails", func(t *testing.T) {
		var evt *Event
		assert.ErrorContains(t, evt.Validate(), "event is nil")
	})

	suite.T().Run("valid event passes", func(t *testing.T) {
		evt := &Event{
			TraceID:   "trace-1",
			EventID:   "event-1",
			Type:      "user.login",
			Component: "auth",
			Timestamp: now,
		}
		assert.NoError(t, evt.Validate())
	})

	suite.T().Run("missing required fields fail", func(t *testing.T) {
		base := Event{
			TraceID:   "trace-1",
			EventID:   "event-1",
			Type:      "user.login",
			Component: "auth",
			Timestamp: now,
		}

		cases := []struct {
			name    string
			mutate  func(*Event)
			contain string
		}{
			{"trace_id", func(e *Event) { e.TraceID = "" }, "trace_id"},
			{"event_id", func(e *Event) { e.EventID = "" }, "event_id"},
			{"type", func(e *Event) { e.Type = "" }, "type"},
			{"component", func(e *Event) { e.Component = "" }, "component"},
			{"timestamp", func(e *Event) { e.Timestamp = time.Time{} }, "timestamp"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				evt := base
				tc.mutate(&evt)
				assert.ErrorContains(t, evt.Validate(), tc.contain)
			})
		}
	})
}
