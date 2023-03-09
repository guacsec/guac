//
// Copyright 2023 The GUAC Authors.
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

package helpers

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func TestVcsUriToSrc(t *testing.T) {

	testCases := []struct {
		uri      string
		wantErr  bool
		expected *model.SourceInputSpec
	}{
		{
			uri:      "git+https://github.com/kubernetes/kubernetes",
			wantErr:  false,
			expected: src("git", "github.com/kubernetes", "kubernetes", nil, nil),
		},
		{
			uri:      "git+https://github.com/kubernetes/kubernetes@3985f0a87ba4277b561e0cac9fba4f594eb8228a",
			wantErr:  false,
			expected: src("git", "github.com/kubernetes", "kubernetes", strP("3985f0a87ba4277b561e0cac9fba4f594eb8228a"), nil),
		},
		{
			uri:      "git+https://github.com/kubernetes/kubernetes@main",
			wantErr:  false,
			expected: src("git", "github.com/kubernetes", "kubernetes", nil, strP("main")),
		},
		{
			uri:      "git+https://github.com/kubernetes@main",
			wantErr:  false,
			expected: src("git", "github.com", "kubernetes", nil, strP("main")),
		},
		{
			uri:     "git://github.com/kubernetes@main",
			wantErr: true,
		},
		{
			uri:     "git://github.com/kubernetes@@main",
			wantErr: true,
		},
		{
			uri:     "github.com/kubernetes@@main",
			wantErr: true,
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("parsing %s", tt.uri), func(t *testing.T) {

			// err == nil should be equivalent to IsVcs
			if IsVcs(tt.uri) == tt.wantErr {
				t.Errorf("expected err but IsVcs returned valid vcs uri")
			}

			got, err := VcsToSrc(tt.uri)
			if tt.wantErr != (err != nil) {
				t.Errorf("want err: %v, got err=%v", tt.wantErr, err)
				return
			}

			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("model SourceInputSpec mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func src(typ, namespace, name string, commit, tag *string) *model.SourceInputSpec {
	return &model.SourceInputSpec{
		Type:      typ,
		Namespace: namespace,
		Name:      name,
		Commit:    commit,
		Tag:       tag,
	}
}
