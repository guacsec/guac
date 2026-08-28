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

package dependencies

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

// GetDependenciesBySortedScorecard returns the same packages as
// GetDependenciesBySortedDependentCnt, worst OpenSSF Scorecard score first.
func GetDependenciesBySortedScorecard(ctx context.Context, gqlClient graphql.Client) ([]PackageName, error) {
	packages, err := findDependentsOfDependencies(ctx, gqlClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependents: %w", err)
	}

	scores, err := scoresByPackageName(ctx, gqlClient, packages)
	if err != nil {
		return nil, err
	}

	var packagesArr []PackageName
	for n, d := range packages {
		pkg := PackageName{Name: n, DependentCount: len(d.dependents)}
		if score, ok := scores[n]; ok {
			pkg.ScorecardScore = &score
		}
		packagesArr = append(packagesArr, pkg)
	}

	sort.Slice(packagesArr, func(i, j int) bool {
		a, b := packagesArr[i], packagesArr[j]
		if (a.ScorecardScore == nil) != (b.ScorecardScore == nil) {
			return b.ScorecardScore == nil
		}
		if a.ScorecardScore != nil && *a.ScorecardScore != *b.ScorecardScore {
			return *a.ScorecardScore < *b.ScorecardScore
		}
		return a.Name < b.Name
	})

	return packagesArr, nil
}

// scoresByPackageName maps a name level purl in wanted to the score of its linked
// source. Packages linked to several sources take the lowest, unscored ones are absent.
func scoresByPackageName(ctx context.Context, gqlClient graphql.Client, wanted map[string]dependencyNode) (map[string]float64, error) {
	scoresBySource, err := scoresBySourceKey(ctx, gqlClient)
	if err != nil {
		return nil, err
	}
	if len(scoresBySource) == 0 {
		return nil, nil
	}

	hasSourceAts, err := model.HasSourceAt(ctx, gqlClient, model.HasSourceAtSpec{})
	if err != nil {
		return nil, fmt.Errorf("error getting package to source links: %w", err)
	}

	scores := make(map[string]float64)
	for _, hasSourceAt := range hasSourceAts.HasSourceAt {
		for _, key := range sourceKeys(hasSourceAt.Source.AllSourceTree) {
			score, ok := scoresBySource[key]
			if !ok {
				continue
			}
			for _, purl := range packageNamePurls(hasSourceAt.Package.AllPkgTree) {
				if _, isWanted := wanted[purl]; !isWanted {
					continue
				}
				if current, seen := scores[purl]; !seen || score < current {
					scores[purl] = score
				}
			}
		}
	}

	return scores, nil
}

// scoresBySourceKey maps a source key to the aggregate score of its most recent
// Scorecard, since only the latest scan describes the repository as it is now.
func scoresBySourceKey(ctx context.Context, gqlClient graphql.Client) (map[string]float64, error) {
	scorecards, err := model.Scorecards(ctx, gqlClient, model.CertifyScorecardSpec{})
	if err != nil {
		return nil, fmt.Errorf("error getting scorecards: %w", err)
	}

	scores := make(map[string]float64)
	scannedAt := make(map[string]time.Time)

	for _, scorecard := range scorecards.Scorecards {
		for _, key := range sourceKeys(scorecard.Source.AllSourceTree) {
			if previous, ok := scannedAt[key]; ok && !newerScan(scorecard.Scorecard, scores[key], previous) {
				continue
			}
			scores[key] = scorecard.Scorecard.AggregateScore
			scannedAt[key] = scorecard.Scorecard.TimeScanned
		}
	}

	return scores, nil
}

// newerScan reports whether a scan supersedes the one already kept for a source.
// Scans stamped with the same time are ordered by score so the result is stable.
func newerScan(scorecard model.AllCertifyScorecardScorecard, keptScore float64, keptTime time.Time) bool {
	if scorecard.TimeScanned.Equal(keptTime) {
		return scorecard.AggregateScore < keptScore
	}
	return scorecard.TimeScanned.After(keptTime)
}

// sourceKeys identifies a repository by type, namespace and name alone, so scans of
// every tag and commit merge: HasSourceAt carries no ref to match the certifier's on.
func sourceKeys(source model.AllSourceTree) []string {
	var keys []string
	for _, namespace := range source.Namespaces {
		for _, name := range namespace.Names {
			// a separator that cannot occur in a namespace, which may itself contain slashes
			keys = append(keys, strings.Join([]string{source.Type, namespace.Namespace, name.Name}, "\x00"))
		}
	}
	return keys
}

// packageNamePurls returns one name level purl per package name in the trie,
// built the same way as the keys in findDependentsOfDependencies.
func packageNamePurls(pkg model.AllPkgTree) []string {
	var purls []string
	for _, namespace := range pkg.Namespaces {
		for _, name := range namespace.Names {
			purls = append(purls, helpers.PkgToPurl(pkg.Type, namespace.Namespace, name.Name, "", "", []string{}))
		}
	}
	return purls
}
