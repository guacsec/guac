//
// Copyright 2026 The GUAC Authors.
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

package scorecard

import (
	"context"
	"slices"
	"testing"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks"
	"github.com/ossf/scorecard/v5/policy"
)

func Test_scorecardRunner_supportedChecks(t *testing.T) {
	runner := scorecardRunner{ctx: context.Background()}
	// License runs off file content so it works at any commit. Contributors and
	// Maintained need repository history, so scorecard only offers them at HEAD.
	input := []string{checks.CheckContributors, checks.CheckLicense, checks.CheckMaintained}

	tests := []struct {
		name      string
		commitSHA string
		want      []string
	}{
		{name: "empty commit keeps every check", commitSHA: "", want: input},
		{name: "HEAD keeps every check", commitSHA: "HEAD", want: input},
		{name: "lowercase head keeps every check", commitSHA: "head", want: input},
		{name: "pinned SHA drops unsupported checks", commitSHA: "98316298749fdd62d3cc99423baec45ae11af662", want: []string{checks.CheckLicense}},
		// A release's TargetCommitish is a branch name, which scorecard also
		// treats as a pinned commit.
		{name: "branch name drops unsupported checks", commitSHA: "main", want: []string{checks.CheckLicense}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runner.supportedChecks(input, test.commitSHA)
			if !slices.Equal(got, test.want) {
				t.Errorf("supportedChecks() = %v, want %v", got, test.want)
			}
		})
	}
}

// GetEnabled is the gate that rejected the unfiltered list with "Unsupported
// RequestType [1] by check: Contributors", so assert the filtered default list
// gets through it for a pinned commit.
func Test_scorecardRunner_supportedChecksPassPolicyGate(t *testing.T) {
	runner := scorecardRunner{ctx: context.Background()}
	filtered := runner.supportedChecks(defaultCheckNames(), "98316298749fdd62d3cc99423baec45ae11af662")

	if len(filtered) == 0 {
		t.Fatal("supportedChecks() returned no checks for a pinned commit")
	}
	if _, err := policy.GetEnabled(nil, filtered, []checker.RequestType{checker.CommitBased}); err != nil {
		t.Errorf("policy.GetEnabled() error = %v, want nil", err)
	}
}

// The HEAD path must keep passing the gate too, so the filter cannot regress
// the common case by dropping checks that are still valid.
func Test_defaultCheckNamesPassPolicyGateAtHead(t *testing.T) {
	if _, err := policy.GetEnabled(nil, defaultCheckNames(), nil); err != nil {
		t.Errorf("policy.GetEnabled() error = %v, want nil", err)
	}
}
