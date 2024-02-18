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

package helpers

import (
	"testing"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func TestLicenseKey(t *testing.T) {
	tests := []struct {
		name string
		lic  *generated.LicenseInputSpec
		want string
	}{
		{
			name: "LicenseRef",
			lic:  &generated.LicenseInputSpec{Name: "LicenseRef-123", Inline: ptrfrom.String("This is the license text.")},
			want: "LicenseRef-123",
		},
		{
			name: "ListVersion",
			lic:  &generated.LicenseInputSpec{Name: "asdf", ListVersion: ptrfrom.String("1.2.3")},
			want: "asdf:1.2.3",
		},
		{
			name: "ListVersion2",
			lic:  &generated.LicenseInputSpec{Name: "qwer", ListVersion: ptrfrom.String("1.2.3")},
			want: "qwer:1.2.3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LicenseKey(tt.lic); got != tt.want {
				t.Errorf("LicenseKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
