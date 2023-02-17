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
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct{}

type demoClient struct {
	packages     []*model.Package
	sources      []*model.Source
	cve          []*model.Cve
	ghsa         []*model.Ghsa
	osv          []*model.Osv
	artifacts    []*model.Artifact
	builders     []*model.Builder
	hashEquals   []*model.HashEqual
	isOccurrence []*model.IsOccurrence
	hasSBOM      []*model.HasSbom
	isDependency []*model.IsDependency
	certifyPkg   []*model.CertifyPkg
	hasSourceAt  []*model.HasSourceAt
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		packages:  []*model.Package{},
		sources:   []*model.Source{},
		cve:       []*model.Cve{},
		ghsa:      []*model.Ghsa{},
		osv:       []*model.Osv{},
		artifacts: []*model.Artifact{},
		builders:  []*model.Builder{},
	}
	registerAllPackages(client)
	registerAllSources(client)
	registerAllCVE(client)
	registerAllGHSA(client)
	registerAllOSV(client)
	registerAllArtifacts(client)
	registerAllBuilders(client)
	registerAllHashEqual(client)
	err := registerAllIsOccurrence(client)
	if err != nil {
		return nil, err
	}
	err = registerAllhasSBOM(client)
	if err != nil {
		return nil, err
	}
	err = registerAllIsDependency(client)
	if err != nil {
		return nil, err
	}
	err = registerAllCertifyPkg(client)
	if err != nil {
		return nil, err
	}
	err = registerAllHasSourceAt(client)
	if err != nil {
		return nil, err
	}
	return client, nil
}
