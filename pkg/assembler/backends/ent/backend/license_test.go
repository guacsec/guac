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

//go:build integration

package backend

import (
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

var l1 = &model.LicenseInputSpec{
	Name:        "BSD-3-Clause",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var l1out = &model.License{
	Name:        "BSD-3-Clause",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var l2 = &model.LicenseInputSpec{
	Name:        "GPL-2.0-or-later",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var l2out = &model.License{
	Name:        "GPL-2.0-or-later",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var l3 = &model.LicenseInputSpec{
	Name:        "MPL-2.0",
	ListVersion: ptrfrom.String("1.23 2020"),
}
var l3out = &model.License{
	Name:        "MPL-2.0",
	ListVersion: ptrfrom.String("1.23 2020"),
}

var inlineLicense = `
Redistribution and use of the MAME code or any derivative works are permitted provided that the following conditions are met:
* Redistributions may not be sold, nor may they be used in a commercial product or activity.
* Redistributions that are modified from the original source must include the complete source code, including the source code for all components used by a binary built from the modified sources. However, as a special exception, the source code distributed need not include anything that is normally distributed (in either source or binary form) with the major components (compiler, kernel, and so on) of the operating system on which the executable runs, unless that component itself accompanies the executable.
* Redistributions must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

var l4 = &model.LicenseInputSpec{
	Name:   "LicenseRef-d58b4101",
	Inline: &inlineLicense,
}
var l4out = &model.License{
	Name:   "LicenseRef-d58b4101",
	Inline: &inlineLicense,
}

func (s *Suite) TestLicense() {
	tests := []struct {
		Name         string
		Ingests      []*model.LicenseInputSpec
		ExpIngestErr bool
		Query        *model.LicenseSpec
		Exp          []*model.License
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.LicenseInputSpec{l1},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{l1out},
		},
		{
			Name:    "Multiple",
			Ingests: []*model.LicenseInputSpec{l1, l2},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{l1out, l2out},
		},
		{
			Name:    "Duplicates",
			Ingests: []*model.LicenseInputSpec{l1, l1, l1},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{l1out},
		},
		{
			Name:    "Query by Name",
			Ingests: []*model.LicenseInputSpec{l1, l2, l3},
			Query: &model.LicenseSpec{
				Name: ptrfrom.String("BSD-3-Clause"),
			},
			Exp: []*model.License{l1out},
		},
		{
			Name:    "Query by Inline",
			Ingests: []*model.LicenseInputSpec{l2, l3, l4},
			Query: &model.LicenseSpec{
				Inline: &inlineLicense,
			},
			Exp: []*model.License{l4out},
		},
		{
			Name:    "Query by ListVersion",
			Ingests: []*model.LicenseInputSpec{l2, l3, l4},
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("1.23 2020"),
			},
			Exp: []*model.License{l3out},
		},
		{
			Name:    "Query by ID",
			Ingests: []*model.LicenseInputSpec{l2, l3, l4},
			Query: &model.LicenseSpec{
				ID: ptrfrom.String("1"),
			},
			Exp: []*model.License{l3out},
		},
		{
			Name:    "Query None",
			Ingests: []*model.LicenseInputSpec{l2, l3, l4},
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("foo"),
			},
			Exp: nil,
		},
		{
			Name:    "Query invalid ID",
			Ingests: []*model.LicenseInputSpec{l1, l2, l3},
			Query: &model.LicenseSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			recordIDs := make([]string, len(test.Ingests))
			for x, i := range test.Ingests {
				lic, err := b.IngestLicense(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[x] = lic.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(recordIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(recordIDs), idIdx, idIdx)
					} else {
						realID := recordIDs[idIdx]
						test.Query.ID = &realID
					}
				}
			}

			got, err := b.Licenses(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessLic)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func lessLic(a, b *model.License) bool {
	return a.Name < b.Name
}

func (s *Suite) TestIngestLicenses() {
	tests := []struct {
		name    string
		ingests []*model.LicenseInputSpec
		exp     []*model.License
	}{
		{
			name:    "Multiple",
			ingests: []*model.LicenseInputSpec{l1, l2, l3, l4},
			exp:     []*model.License{{}, {}, {}, {}},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			got, err := b.IngestLicenses(ctx, test.ingests)
			if err != nil {
				t.Fatalf("ingest error: %v", err)
				return
			}
			if diff := cmp.Diff(test.exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
