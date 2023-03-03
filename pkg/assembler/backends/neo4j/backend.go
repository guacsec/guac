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

package neo4jBackend

import (
	"context"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

const (
	namespaces    string = "namespaces"
	names         string = namespaces + ".names"
	versions      string = names + ".versions"
	cvdID         string = "cveId"
	origin        string = "origin"
	collector     string = "collector"
	justification string = "justification"
)

type Neo4jConfig struct {
	User     string
	Pass     string
	Realm    string
	DBAddr   string
	TestData bool
}

type neo4jClient struct {
	driver neo4j.Driver
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	config := args.(*Neo4jConfig)
	token := neo4j.BasicAuth(config.User, config.Pass, config.Realm)
	driver, err := neo4j.NewDriver(config.DBAddr, token)
	if err != nil {
		return nil, err
	}

	if err = driver.VerifyConnectivity(); err != nil {
		driver.Close()
		return nil, err
	}
	client := &neo4jClient{driver}
	/* if config.TestData {
		err = registerAllPackages(client)
		if err != nil {
			return nil, err
		}
		err = registerAllArtifacts(client)
		if err != nil {
			return nil, err
		}
		err = registerAllBuilders(client)
		if err != nil {
			return nil, err
		}
		err = registerAllSources(client)
		if err != nil {
			return nil, err
		}
		err = registerAllCVE(client)
		if err != nil {
			return nil, err
		}
		err = registerAllGHSA(client)
		if err != nil {
			return nil, err
		}
		err = registerAllOSV(client)
		if err != nil {
			return nil, err
		}
	} */
	return client, nil
}

func matchProperties(sb *strings.Builder, firstMatch bool, label, property string, resolver string) {
	if firstMatch {
		sb.WriteString(" WHERE ")
	} else {
		sb.WriteString(" AND ")
	}
	sb.WriteString(label)
	sb.WriteString(".")
	sb.WriteString(property)
	sb.WriteString(" = ")
	sb.WriteString(resolver)
}

// getPreloads get the specific graphQL query fields that are requested.
// graphql.CollectAllFields only provides the top level fields and none of the nested fields below it.
// getPreloads recursively goes through the fields and retrieves each nested field below it.
// for example:
/*
  type
  namespaces {
    namespace
    names {
      name
      tag
      commit
    }
  }
  will return:
  fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
*/
func getPreloads(ctx context.Context) []string {
	visited := make(map[string]bool)
	return getNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"", visited)
}

func getNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string, visited map[string]bool) []string {
	preloads := []string{}
	for _, column := range fields {
		prefixColumn := getPreloadString(prefix, column.Name)
		if visited[prefixColumn] {
			continue
		}
		visited[prefixColumn] = true
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads, getNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn, visited)...)
	}
	return preloads
}

func getPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}
	return name
}
