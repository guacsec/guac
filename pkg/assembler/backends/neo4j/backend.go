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

func (c *neo4jClient) Artifacts(ctx context.Context) ([]*model.Artifact, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := "MATCH (n:Artifact) return n.digest, n.name"
			result, err := tx.Run(query, nil)
			if err != nil {
				return nil, err
			}

			var artifacts []*model.Artifact
			for result.Next() {
				artifact := model.Artifact{
					Digest: result.Record().Values[0].(string),
				}
				if result.Record().Values[1] != nil {
					packageName := result.Record().Values[1].(string)
					artifact.Name = &packageName
				}
				artifacts = append(artifacts, &artifact)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return artifacts, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Artifact), nil
}

func (c *neo4jClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	panic(fmt.Errorf("not implemented: Packages - packages in Neo4j backend"))
}
