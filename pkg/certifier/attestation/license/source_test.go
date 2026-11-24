//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
)

func TestSourceInputFromCD(t *testing.T) {
	revision := "9e3b772b8cabbd8cadc7522ebe3dde3279e79d9e"

	tests := []struct {
		name          string
		source        *SourceLocation
		wantType      string
		wantNamespace string
		wantName      string
		wantCommit    *string
		wantTag       *string
	}{
		{
			name: "github",
			source: &SourceLocation{
				Type:      "git",
				Provider:  "github",
				Namespace: "facebook",
				Name:      "react",
				Revision:  revision,
				URL:       "https://github.com/facebook/react/tree/" + revision,
			},
			wantType:      "git",
			wantNamespace: "github.com/facebook",
			wantName:      "react",
			wantCommit:    &revision,
		},
		{
			name: "gitlab",
			source: &SourceLocation{
				Type:      "git",
				Provider:  "gitlab",
				Namespace: "group",
				Name:      "project",
				Revision:  revision,
				URL:       "https://gitlab.com/group/project/-/tree/" + revision,
			},
			wantType:      "git",
			wantNamespace: "gitlab.com/group",
			wantName:      "project",
			wantCommit:    &revision,
		},
		{
			name: "bitbucket",
			source: &SourceLocation{
				Type:      "git",
				Provider:  "bitbucket",
				Namespace: "atlassian",
				Name:      "python-bitbucket",
				Revision:  revision,
				URL:       "https://bitbucket.org/atlassian/python-bitbucket/src/" + revision,
			},
			wantType:      "git",
			wantNamespace: "bitbucket.org/atlassian",
			wantName:      "python-bitbucket",
			wantCommit:    &revision,
		},
		{
			name: "unknown provider keeps raw fields",
			source: &SourceLocation{
				Type:      "git",
				Provider:  "unknown",
				Namespace: "facebook",
				Name:      "react",
				Revision:  revision,
				URL:       "https://example.com/facebook/react/tree/" + revision,
			},
			wantType:      "git",
			wantNamespace: "facebook",
			wantName:      "react",
			wantCommit:    &revision,
		},
		{
			name: "non-git type keeps raw fields",
			source: &SourceLocation{
				Type:      "sourcearchive",
				Provider:  "mavencentral",
				Namespace: "org.apache.commons",
				Name:      "commons-text",
				Revision:  "1.9",
				URL:       "https://repo1.maven.org/maven2/org/apache/commons/commons-text/1.9/commons-text-1.9-sources.jar",
			},
			wantType:      "sourcearchive",
			wantNamespace: "org.apache.commons",
			wantName:      "commons-text",
			wantTag:       ptrfrom.String("1.9"),
		},
		{
			name: "provider case insensitive",
			source: &SourceLocation{
				Type:      "git",
				Provider:  "GitHub",
				Namespace: "facebook",
				Name:      "react",
				Revision:  revision,
			},
			wantType:      "git",
			wantNamespace: "github.com/facebook",
			wantName:      "react",
			wantCommit:    &revision,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SourceInputFromCD(tt.source)
			assert.Equal(t, tt.wantType, got.Type)
			assert.Equal(t, tt.wantNamespace, got.Namespace)
			assert.Equal(t, tt.wantName, got.Name)
			assert.Equal(t, tt.wantCommit, got.Commit)
			assert.Equal(t, tt.wantTag, got.Tag)
		})
	}
}
