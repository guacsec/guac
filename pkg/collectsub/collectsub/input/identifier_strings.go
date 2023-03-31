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

// input defines collectsub structs that can be used for human/application inputs
// that do not necessarily find it convenient to use protobuf (e.g.
package input

import (
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
)

// TODO: write tests for this.
func IdentifierStringsSliceToCollectEntries(i []*parser_common.IdentifierStrings) []*pb.CollectEntry {
	entries := []*pb.CollectEntry{}
	for _, ii := range i {
		entries = append(entries, identifierStringsToCollectEntry(ii)...)
	}
	return entries
}

func identifierStringsToCollectEntry(i *parser_common.IdentifierStrings) []*pb.CollectEntry {
	entries := []*pb.CollectEntry{}
	for _, v := range i.OciStrings {
		entries = append(entries, &pb.CollectEntry{
			Type:  pb.CollectDataType_DATATYPE_OCI,
			Value: v,
		})
	}

	for _, v := range i.VcsStrings {
		entries = append(entries, &pb.CollectEntry{
			Type:  pb.CollectDataType_DATATYPE_GIT,
			Value: v,
		})
	}

	for _, v := range i.PurlStrings {
		entries = append(entries, &pb.CollectEntry{
			Type:  pb.CollectDataType_DATATYPE_PURL,
			Value: v,
		})
	}

	for _, v := range i.UnclassifiedStrings {
		e, err := guessUnknownIdentifierString(v)
		if err == nil {
			entries = append(entries, e)
		}
	}

	return entries
}

// tries to guess what the collect entry for the string is and returns
// an error if it can't figure it out.
func guessUnknownIdentifierString(s string) (*pb.CollectEntry, error) {
	if strings.HasPrefix(s, "index.docker.io") ||
		strings.HasPrefix(s, "ghcr.io") ||
		strings.HasPrefix(s, "gcr.io") {
		return &pb.CollectEntry{
			Type:  pb.CollectDataType_DATATYPE_OCI,
			Value: s,
		}, nil
	}

	if _, err := helpers.PurlToPkg(s); err == nil {
		return &pb.CollectEntry{
			Type:  pb.CollectDataType_DATATYPE_PURL,
			Value: s,
		}, nil
	}
	return nil, fmt.Errorf("unable to guess collect entry")
}
