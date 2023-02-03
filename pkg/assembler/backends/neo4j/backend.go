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

package backend

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type Neo4jCredentials struct {
	User   string
	Pass   string
	Realm  string
	DBAddr string
}

type neo4jClient struct {
	driver neo4j.Driver
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	creds := args.(*Neo4jCredentials)
	token := neo4j.BasicAuth(creds.User, creds.Pass, creds.Realm)
	driver, err := neo4j.NewDriver(creds.DBAddr, token)
	if err != nil {
		return nil, err
	}

	if err = driver.VerifyConnectivity(); err != nil {
		driver.Close()
		return nil, err
	}

	return &neo4jClient{driver}, nil
}

func (c *neo4jClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	panic(fmt.Errorf("not implemented: Packages - packages in Neo4j backend"))
}

func (c *neo4jClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	panic(fmt.Errorf("not implemented: Sources - sources in Neo4j backend"))
}

func (c *neo4jClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	panic(fmt.Errorf("not implemented: Cve - cve in Neo4j backend"))
}

func (c *neo4jClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: Ghsa - ghsa in Neo4j backend"))
}

func (c *neo4jClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	panic(fmt.Errorf("not implemented: Osv - osv in Neo4j backend"))
}

func (c *neo4jClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	panic(fmt.Errorf("not implemented: Artifacts - artifacts in Neo4j backend"))
}

func (c *neo4jClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	panic(fmt.Errorf("not implemented: Builders - builders in Neo4j backend"))
}
