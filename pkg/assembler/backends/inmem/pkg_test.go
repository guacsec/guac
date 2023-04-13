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

package inmem

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_pkgNamespaceStruct_ID(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		want uint32
	}{{
		name: "getID",
		id:   643,
		want: 643,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNamespaceStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgNamespaceStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNameStruct_ID(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		want uint32
	}{{
		name: "getID",
		id:   643,
		want: 643,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNameStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgNameStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionStruct_ID(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		want uint32
	}{{
		name: "getID",
		id:   643,
		want: 643,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgVersionStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionNode_ID(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		want uint32
	}{{
		name: "getID",
		id:   643,
		want: 643,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionNode{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgVersionNode.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNamespaceStruct_Neighbors(t *testing.T) {
	type fields struct {
		id         uint32
		namespaces pkgNamespaceMap
	}
	tests := []struct {
		name   string
		fields fields
		want   []uint32
	}{{
		name: "pkgNamespaceStruct Neighbors",
		fields: fields{
			id:         uint32(23),
			namespaces: pkgNamespaceMap{"test": &pkgNameStruct{id: uint32(24)}},
		},
		want: []uint32{uint32(24)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNamespaceStruct{
				id:         tt.fields.id,
				namespaces: tt.fields.namespaces,
			}
			if got := n.Neighbors(nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgNamespaceStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNameStruct_Neighbors(t *testing.T) {
	type fields struct {
		id        uint32
		parent    uint32
		namespace string
		names     pkgNameMap
	}
	tests := []struct {
		name   string
		fields fields
		want   []uint32
	}{{
		name: "pkgNameStruct Neighbors",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			namespace: "test",
			names:     pkgNameMap{"test": &pkgVersionStruct{id: uint32(24)}},
		},
		want: []uint32{uint32(24), uint32(22)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNameStruct{
				id:        tt.fields.id,
				parent:    tt.fields.parent,
				namespace: tt.fields.namespace,
				names:     tt.fields.names,
			}
			if got := n.Neighbors(nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgNameStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionStruct_Neighbors(t *testing.T) {
	type fields struct {
		id                uint32
		parent            uint32
		versions          pkgVersionList
		srcMapLinks       []uint32
		isDependencyLinks []uint32
		badLinks          []uint32
		goodLinks         []uint32
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []uint32
	}{{
		name: "srcMapLinks",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			versions:    pkgVersionList{&pkgVersionNode{id: uint32(24)}},
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
		want:         []uint32{22, 24, 343, 546},
	}, {
		name: "isDependencyLinks",
		fields: fields{
			id:                uint32(23),
			parent:            uint32(22),
			versions:          pkgVersionList{&pkgVersionNode{id: uint32(24)}},
			isDependencyLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
		want:         []uint32{22, 24, 2324, 1234},
	}, {
		name: "badLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			versions: pkgVersionList{&pkgVersionNode{id: uint32(24)}},
			badLinks: []uint32{445, 1232244},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
		want:         []uint32{22, 24, 445, 1232244},
	}, {
		name: "goodLinks",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			versions:  pkgVersionList{&pkgVersionNode{id: uint32(24)}},
			goodLinks: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
		want:         []uint32{22, 24, 987, 9876},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionStruct{
				id:                tt.fields.id,
				parent:            tt.fields.parent,
				versions:          tt.fields.versions,
				srcMapLinks:       tt.fields.srcMapLinks,
				isDependencyLinks: tt.fields.isDependencyLinks,
				badLinks:          tt.fields.badLinks,
				goodLinks:         tt.fields.goodLinks,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgVersionStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionNode_Neighbors(t *testing.T) {
	type fields struct {
		id                uint32
		parent            uint32
		srcMapLinks       []uint32
		isDependencyLinks []uint32
		occurrences       []uint32
		certifyVulnLinks  []uint32
		hasSBOMs          []uint32
		vexLinks          []uint32
		badLinks          []uint32
		goodLinks         []uint32
		pkgEquals         []uint32
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []uint32
	}{{
		name: "srcMapLinks",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
		want:         []uint32{22, 343, 546},
	}, {
		name: "isDependencyLinks",
		fields: fields{
			id:                uint32(23),
			parent:            uint32(22),
			isDependencyLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
		want:         []uint32{22, 2324, 1234},
	}, {
		name: "occurrences",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			occurrences: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsOccurrence: true},
		want:         []uint32{22, 2324, 1234},
	}, {
		name: "certifyVulnLinks",
		fields: fields{
			id:               uint32(23),
			parent:           uint32(22),
			certifyVulnLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyVuln: true},
		want:         []uint32{22, 2324, 1234},
	}, {
		name: "hasSBOMs",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			hasSBOMs: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSbom: true},
		want:         []uint32{22, 2324, 1234},
	}, {
		name: "vexLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			vexLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyVexStatement: true},
		want:         []uint32{22, 2324, 1234},
	}, {
		name: "badLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			badLinks: []uint32{445, 1232244},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
		want:         []uint32{22, 445, 1232244},
	}, {
		name: "goodLinks",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			goodLinks: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
		want:         []uint32{22, 987, 9876},
	}, {
		name: "pkgEquals",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			pkgEquals: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackagePkgEqual: true},
		want:         []uint32{22, 987, 9876},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionNode{
				id:                tt.fields.id,
				parent:            tt.fields.parent,
				srcMapLinks:       tt.fields.srcMapLinks,
				isDependencyLinks: tt.fields.isDependencyLinks,
				occurrences:       tt.fields.occurrences,
				certifyVulnLinks:  tt.fields.certifyVulnLinks,
				hasSBOMs:          tt.fields.hasSBOMs,
				vexLinks:          tt.fields.vexLinks,
				badLinks:          tt.fields.badLinks,
				goodLinks:         tt.fields.goodLinks,
				pkgEquals:         tt.fields.pkgEquals,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgVersionNode.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}
