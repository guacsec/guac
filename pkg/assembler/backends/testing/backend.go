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

package testing

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct{}

// IDs: We have a global ID for all nodes that have references to/from.
// Since we always ingest data and never remove, we can keep this global and
// increment it as needed.
// For fast retrieval, we also keep a map from ID from nodes that have it.
// IDs are stored as string in graphql even though we ask for integers
// See https://github.com/99designs/gqlgen/issues/2561
type hasID interface {
	getID() uint32
}

type indexType map[uint32]hasID

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() uint32 {
	return atomic.AddUint32(&c.id, 1)
}

type demoClient struct {
	artifacts           []*model.Artifact
	builders            []*model.Builder
	hashEquals          []*model.HashEqual
	isOccurrence        []*model.IsOccurrence
	hasSBOM             []*model.HasSbom
	certifyPkg          []*model.CertifyPkg
	certifyVuln         []*model.CertifyVuln
	certifyScorecard    []*model.CertifyScorecard
	certifyBad          []*model.CertifyBad
	isVulnerability     []*model.IsVulnerability
	certifyVEXStatement []*model.CertifyVEXStatement
	hasSLSA             []*model.HasSlsa
	id                  uint32
	index               indexType
	packages            pkgTypeMap
	sources             srcTypeMap
	hasSources          hasSrcList
	isDependencies      isDependencyList
	osvs                osvMap
	ghsas               ghsaMap
	cves                cveMap
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		artifacts:           []*model.Artifact{},
		builders:            []*model.Builder{},
		hashEquals:          []*model.HashEqual{},
		isOccurrence:        []*model.IsOccurrence{},
		hasSBOM:             []*model.HasSbom{},
		certifyPkg:          []*model.CertifyPkg{},
		certifyVuln:         []*model.CertifyVuln{},
		certifyScorecard:    []*model.CertifyScorecard{},
		certifyBad:          []*model.CertifyBad{},
		isVulnerability:     []*model.IsVulnerability{},
		certifyVEXStatement: []*model.CertifyVEXStatement{},
		hasSLSA:             []*model.HasSlsa{},
		index:               indexType{},
		packages:            pkgTypeMap{},
		sources:             srcTypeMap{},
		hasSources:          hasSrcList{},
		isDependencies:      isDependencyList{},
		osvs:                osvMap{},
		ghsas:               ghsaMap{},
		cves:                cveMap{},
	}
	registerAllPackages(client)
	registerAllSources(client)
	registerAllCVE(client)
	registerAllGHSA(client)
	registerAllOSV(client)
	registerAllArtifacts(client)
	registerAllBuilders(client)

	return client, nil
}

func GetEmptyBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		artifacts:           []*model.Artifact{},
		builders:            []*model.Builder{},
		hashEquals:          []*model.HashEqual{},
		isOccurrence:        []*model.IsOccurrence{},
		hasSBOM:             []*model.HasSbom{},
		certifyPkg:          []*model.CertifyPkg{},
		certifyVuln:         []*model.CertifyVuln{},
		certifyScorecard:    []*model.CertifyScorecard{},
		certifyBad:          []*model.CertifyBad{},
		isVulnerability:     []*model.IsVulnerability{},
		certifyVEXStatement: []*model.CertifyVEXStatement{},
		hasSLSA:             []*model.HasSlsa{},
		index:               indexType{},
		packages:            pkgTypeMap{},
		sources:             srcTypeMap{},
		hasSources:          hasSrcList{},
		isDependencies:      isDependencyList{},
		osvs:                osvMap{},
		ghsas:               ghsaMap{},
		cves:                cveMap{},
	}
	return client, nil
}

func nodeID(id uint32) string {
	return fmt.Sprintf("%d", id)
}

func noMatch(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return false
}

func noMatchInput(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return value != ""
}

func nilToEmpty(input *string) string {
	if input == nil {
		return ""
	}
	return *input
}

func toLower(filter *string) *string {
	if filter != nil {
		lower := strings.ToLower(*filter)
		return &lower
	}
	return nil
}
