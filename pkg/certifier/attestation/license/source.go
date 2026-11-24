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
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

// cdProviderHosts maps ClearlyDefined git provider names to the VCS host used
// by helpers.VcsToSrc. Other GUAC ingestion paths (deps.dev, GitHub collector,
// SLSA, Scorecard) produce the same host-qualified namespace, e.g.
// "github.com/facebook" rather than ClearlyDefined's bare "facebook".
var cdProviderHosts = map[string]string{
	"github":    "github.com",
	"gitlab":    "gitlab.com",
	"bitbucket": "bitbucket.org",
}

// SourceInputFromCD returns the canonical GUAC source identity for a
// ClearlyDefined source location. For known git providers it builds a plain
// repository URL from Provider/Namespace/Name and runs it through
// helpers.VcsToSrc so the resulting Type/Namespace/Name match every other
// ingestion path. Unknown providers, non-git types, and VcsToSrc failures keep
// the raw ClearlyDefined fields. The Coordinate sent back to ClearlyDefined
// must still use the raw fields; only the GUAC source identity is normalized.
func SourceInputFromCD(loc *SourceLocation) *generated.SourceInputSpec {
	srcType, namespace, name := loc.Type, loc.Namespace, loc.Name
	if loc.Type == "git" {
		if host, ok := cdProviderHosts[strings.ToLower(loc.Provider)]; ok {
			if src, err := helpers.VcsToSrc(fmt.Sprintf("https://%s/%s/%s", host, loc.Namespace, loc.Name)); err == nil {
				srcType, namespace, name = src.Type, src.Namespace, src.Name
			}
		}
	}
	return helpers.SourceToSourceInput(srcType, namespace, name, &loc.Revision)
}
