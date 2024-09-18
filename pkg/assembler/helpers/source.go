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
	"fmt"
	"strings"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type SrcIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
}

func SrcServerKey(src *model.SourceInputSpec) SrcIds {
	return guacSrcId(src.Type, src.Namespace, src.Name, src.Tag, src.Commit)
}

func SrcClientKey(src *generated.SourceInputSpec) SrcIds {
	return guacSrcId(src.Type, src.Namespace, src.Name, src.Tag, src.Commit)
}

func guacSrcId(srcType, namespace, name string, stcTag, srcCommit *string) SrcIds {
	ids := SrcIds{}

	ids.TypeId = srcType

	var ns string
	if namespace != "" {
		ns = namespace
	} else {
		ns = guacEmpty
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)

	var tag string
	if stcTag != nil {
		if *stcTag != "" {
			tag = *stcTag
		} else {
			tag = guacEmpty
		}
	}

	var commit string
	if srcCommit != nil {
		if *srcCommit != "" {
			commit = *srcCommit
		} else {
			commit = guacEmpty
		}
	}

	ids.NameId = fmt.Sprintf("%s::%s::%s::%s?", ids.NamespaceId, name, tag, commit)
	return ids
}

// convert src ID to source input that will be used by the clearly defined parser
// example:  "uri": "sourcearchive::org.apache.commons::commons-text::1.9::?"
func GuacSrcIdToSourceInput(srcID string) (*generated.SourceInputSpec, error) {

	srcIDSplit := strings.Split(srcID, "::")

	if len(srcIDSplit) != 5 {
		return nil, fmt.Errorf("srcID does not have required length")
	}

	srcInput := &generated.SourceInputSpec{
		Type: srcIDSplit[0],
		Name: srcIDSplit[2],
	}

	if srcIDSplit[1] == guacEmpty {
		srcInput.Namespace = ""
	} else {
		srcInput.Namespace = srcIDSplit[1]
	}

	if srcIDSplit[3] != "" {
		if srcIDSplit[3] == guacEmpty {
			srcInput.Tag = ptrfrom.String("")
		} else {
			srcInput.Tag = &srcIDSplit[3]
		}
	}

	trimmedCommit := strings.TrimRight(srcIDSplit[4], "?")
	if trimmedCommit != "" {
		if trimmedCommit == guacEmpty {
			srcInput.Commit = ptrfrom.String("")
		} else {
			srcInput.Commit = &trimmedCommit
		}
	}

	return srcInput, nil
}

func SourceToSourceInput(srcType, namespace, name string, revision *string) *generated.SourceInputSpec {
	srcInput := &generated.SourceInputSpec{
		Type:      srcType,
		Namespace: namespace,
		Name:      name,
	}

	if revision != nil {
		if isCommit(*revision) {
			srcInput.Commit = revision
		} else {
			srcInput.Tag = revision
		}
	}
	return srcInput
}
