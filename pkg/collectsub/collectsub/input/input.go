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
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
)

type CollectEntryInput struct {
	// Type string based on protobuf enum CollectDataType
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (e *CollectEntryInput) Convert() *pb.CollectEntry {
	return &pb.CollectEntry{
		Type:  pb.CollectDataType(pb.CollectDataType_value[e.Type]),
		Value: e.Value,
	}
}

func ConvertCollectEntry(e *pb.CollectEntry) CollectEntryInput {
	return CollectEntryInput{
		Type:  pb.CollectDataType_name[int32(e.GetType())],
		Value: e.GetValue(),
	}
}

type CollectEntryFilterInput struct {
	// Type string based on protobuf enum CollectDataType
	Type string `json:"type,omitempty"`
	Glob string `json:"value,omitempty"`
}

func (e *CollectEntryFilterInput) Convert() *pb.CollectEntryFilter {
	return &pb.CollectEntryFilter{
		Type: pb.CollectDataType(pb.CollectDataType_value[e.Type]),
		Glob: e.Glob,
	}
}

func ConvertCollectEntryFilter(e *pb.CollectEntryFilter) CollectEntryFilterInput {
	return CollectEntryFilterInput{
		Type: pb.CollectDataType_name[int32(e.GetType())],
		Glob: e.Glob,
	}
}
