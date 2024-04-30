// Copyright 2024, Northwood Labs
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crowdstrike

import (
	"time"
)

type (
	OAuthResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	ListMeta struct {
		QueryTime float64 `json:"query_time"`
		PoweredBy string  `json:"powered_by"`
		TraceID   string  `json:"trace_id"`
	}

	ListResp struct {
		Meta      ListMeta        `json:"meta"`
		Errors    []interface{}   `json:"errors"`
		Resources []ListResources `json:"resources"`
	}

	ListResources struct {
		ReleaseDate time.Time `json:"release_date"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Platform    string    `json:"platform"`
		OS          string    `json:"os"`
		OSVersion   string    `json:"os_version"`
		Sha256      string    `json:"sha256"`
		Version     string    `json:"version"`
		FileType    string    `json:"file_type"`
		FileSize    int64     `json:"file_size"`
	}
)
