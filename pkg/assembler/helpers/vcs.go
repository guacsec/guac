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
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

// Following the definition of VCS uri from the SPDX documentation:
// https://spdx.github.io/spdx-spec/v2.3/package-information/#771-description
//
// <vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>]

func IsVcs(s string) bool {
	_, err := VcsToSrc(s)
	return err == nil
}

func VcsToSrc(vcsUri string) (*model.SourceInputSpec, error) {
	u, err := url.Parse(vcsUri)
	if err != nil {
		return nil, err
	}

	m := &model.SourceInputSpec{}

	if u.Scheme == "https" {
		if u.Host == "go.googlesource.com" || u.Host == "github.com" || u.Host == "gitlab.com" || strings.Contains(u.Host, "bitbucket") {
			m.Type = "git"
		} else {
			return nil, fmt.Errorf("scheme has unknown source type: %s", u.Host)
		}

	} else {
		// Should be <vcs_tool>+<transport>
		schemeSp := strings.Split(u.Scheme, "+")
		if len(schemeSp) != 2 {
			return nil, fmt.Errorf("scheme should be in format <vcs_tool>+<transport>, got %s", u.Scheme)
		}
		m.Type = schemeSp[0]
	}
	m.Namespace = u.Host
	idx := strings.LastIndex(u.Path, "/")

	if idx > 0 {
		m.Name = u.Path[idx+1:]
		m.Namespace += u.Path[:idx]
	} else {
		m.Name = strings.TrimPrefix(u.Path, "/")
	}

	sp := strings.Split(m.Name, "@")
	if len(sp) > 2 {
		return nil, fmt.Errorf("uri contains more than 1 @")
	}

	m.Name = sp[0]
	if len(sp) == 2 {
		tag := sp[1]
		if isCommit(tag) {
			m.Commit = &tag
		} else {
			m.Tag = &tag
		}
	}

	return m, nil
}

func isCommit(s string) bool {
	// for now assume commit is sha1 string
	if len(s) != 160/4 {
		return false
	}

	_, err := hex.DecodeString(s)
	return err == nil
}
