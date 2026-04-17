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

package server

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// FindMatchingPurls returns the purls of every package version in the graph
// whose purl is "associated with" the input purl, per the semantics of
// GET /v0/package/{purl}.
//
// An input purl is treated as a template: components that it specifies act as
// exact-match constraints, while omitted components act as wildcards.
// Qualifiers are matched as a subset — a package qualifies if its qualifier
// map contains every qualifier in the input, but may contain additional
// qualifiers. For example, the input "pkg:foo/bar?a=b" matches both
// "pkg:foo/bar?a=b" and "pkg:foo/bar?a=b&c=d".
//
// The graphql backend's qualifier filter is an exact-equality check, so the
// superset semantics and the "omitted version is a wildcard" semantics are
// applied on the client side here.
func FindMatchingPurls(ctx context.Context, gqlClient graphql.Client, inputPurl string) ([]string, error) {
	logger := logging.FromContext(ctx)

	inputSpec, err := assembler_helpers.PurlToPkg(inputPurl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl %q: %w", inputPurl, err)
	}

	filter := pkgSpecForLooseMatch(inputSpec)

	response, err := gql.Packages(ctx, gqlClient, filter)
	if err != nil {
		logger.Errorf("Packages query returned error: %v", err)
		return nil, helpers.Err502
	}
	if response == nil {
		logger.Errorf("Packages query returned a nil response")
		return nil, helpers.Err500
	}

	wantVersion := strDeref(inputSpec.Version)
	wantSubpath := strDeref(inputSpec.Subpath)
	wantQualifiers := make(map[string]string, len(inputSpec.Qualifiers))
	for _, q := range inputSpec.Qualifiers {
		wantQualifiers[q.Key] = q.Value
	}

	seen := map[string]struct{}{}
	purls := []string{}
	for _, v := range helpers.GetVersionsOfPackagesResponse(response.GetPackages()) {
		if wantVersion != "" && v.Version != wantVersion {
			continue
		}
		if wantSubpath != "" && v.Subpath != wantSubpath {
			continue
		}
		if !qualifiersContain(v.Qualifiers, wantQualifiers) {
			continue
		}
		if _, dup := seen[v.Purl]; dup {
			continue
		}
		seen[v.Purl] = struct{}{}
		purls = append(purls, v.Purl)
	}
	return purls, nil
}

// pkgSpecForLooseMatch builds the GraphQL PkgSpec for the server-side portion
// of the loose purl match: an exact match on type/namespace/name (all of which
// are populated for any parseable purl) and on any non-empty version or
// subpath. Qualifier matching is left entirely to the caller so we can
// implement subset semantics on top of the backend's exact-equality filter.
func pkgSpecForLooseMatch(inputSpec *gql.PkgInputSpec) gql.PkgSpec {
	namespace := strDeref(inputSpec.Namespace)
	filter := gql.PkgSpec{
		Type:      &inputSpec.Type,
		Namespace: &namespace,
		Name:      &inputSpec.Name,
	}
	if version := strDeref(inputSpec.Version); version != "" {
		filter.Version = &version
	}
	if subpath := strDeref(inputSpec.Subpath); subpath != "" {
		filter.Subpath = &subpath
	}
	return filter
}

func qualifiersContain(
	have []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier,
	want map[string]string,
) bool {
	if len(want) == 0 {
		return true
	}
	haveMap := make(map[string]string, len(have))
	for _, q := range have {
		haveMap[q.Key] = q.Value
	}
	for k, v := range want {
		if hv, ok := haveMap[k]; !ok || hv != v {
			return false
		}
	}
	return true
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
