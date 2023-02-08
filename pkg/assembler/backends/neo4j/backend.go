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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
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
	if config.TestData {
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
	}
	return client, nil
}

func matchWhere(sb *strings.Builder, label, property string, resolver string) error {
	_, err := sb.WriteString(" WHERE ")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(label)
	if err != nil {
		return err
	}
	_, err = sb.WriteString(".")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(property)
	if err != nil {
		return err
	}
	_, err = sb.WriteString(" = ")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(resolver)
	if err != nil {
		return err
	}

	return nil
}

func matchAnd(sb *strings.Builder, label, property string, resolver string) error {
	_, err := sb.WriteString(" AND ")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(label)
	if err != nil {
		return err
	}
	_, err = sb.WriteString(".")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(property)
	if err != nil {
		return err
	}
	_, err = sb.WriteString(" = ")
	if err != nil {
		return err
	}
	_, err = sb.WriteString(resolver)
	if err != nil {
		return err
	}

	return nil
}
