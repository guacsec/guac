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
