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

package core

// SystemLanguage is the default language code for the system.
const SystemLanguage = "en"

// SystemNamespace is the default namespace for system translations.
const SystemNamespace = "system"

// LanguagePreferenceOrder defines the priority of languages for fallback.
var LanguagePreferenceOrder = map[string]int{
	"en-US": 0,
	"en":    1,
}

