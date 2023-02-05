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
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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

// TODO: Rewrite this with the new trie structure
func createIndices(client graphdb.Client) error {
	indices := map[string][]string{
		"Artifact":      {"digest", "name"},
		"Package":       {"purl", "name"},
		"Metadata":      {"id"},
		"Attestation":   {"digest"},
		"Vulnerability": {"id"},
	}

	for label, attributes := range indices {
		for _, attribute := range attributes {
			err := assembler.CreateIndexOn(client, label, attribute)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *neo4jClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	/* 	var sb strings.Builder

	   	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	   	defer session.Close()

	   	result, err := session.ReadTransaction(
	   		func(tx neo4j.Transaction) (interface{}, error) {
	   			//graphdb.ReadQuery(client, "MATCH (p:Package) WHERE p.purl = $rootPurl WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2", map[string]any{"rootPurl": parentPurl})

	   			sb.WriteString("MATCH (n:Pkg)-[:PkgHasType]->(t:PkgType)-[:PkgHasNamespace]->(w:PkgNamespace)-[:PkgHasName]->(r:PkgName)-[:PkgHasVersion]->(y:PkgVersion) WHERE t.type = $pkgType AND w.namespace = $pkgNamespace AND r.name = $pkgName AND y.version = $pkgVerion AND y.subpath = $pkgSubpath")

	   			for _, qualifier := range pkgSpec.Qualifiers {
	   				matchQualifier(&sb, "y", qualifier.Key, *qualifier.Value)
	   			}

	   			sb.WriteString("RETURN t.type, w.namespace, r.name, y.version, y.subpath")

	   			for _, qualifier := range pkgSpec.Qualifiers {
	   				returnQualifier(&sb, "y", qualifier.Key)
	   			}

	   			result, err := tx.Run(sb.String(), map[string]any{"pkgType": pkgSpec.Type,
	   				"pkgNamespace": pkgSpec.Namespace,
	   				"pkgName":      pkgSpec.Name,
	   				"pkgVersion":   pkgSpec.Version,
	   				"pkgSubpath":   pkgSpec.Subpath})
	   			if err != nil {
	   				return nil, err
	   			}

	   			packageName := map[string][]*model.PackageVersion{}
	   			packageNamespace := map[string][]*model.PackageName{}
	   			packageType := map[string][]*model.Package{}
	   			for result.Next() {
	   				pkgQualifier := &model.PackageQualifier{
	   					Key:   "",
	   					Value: "",
	   				}
	   				pkgVersion := &model.PackageVersion{
	   					Version:    result.Record().Values[3].(string),
	   					Subpath:    result.Record().Values[4].(string),
	   					Qualifiers: []*model.PackageQualifier{pkgQualifier},
	   				}
	   				pkgName := &model.PackageName{
	   					Name:     result.Record().Values[2].(string),
	   					Versions: []*model.PackageVersion{pkgVersion},
	   				}
	   				packageName[result.Record().Values[2].(string)] = append(packageName[result.Record().Values[2].(string)], pkgVersion)
	   				pkgNamespace := &model.PackageNamespace{
	   					Namespace: result.Record().Values[1].(string),
	   					Names:     []*model.PackageName{pkgName},
	   				}
	   				packageNamespace[result.Record().Values[1].(string)] = append(packageNamespace[result.Record().Values[1].(string)], pkgName)
	   				pkg := &model.Package{
	   					Type:       result.Record().Values[0].(string),
	   					Namespaces: []*model.PackageNamespace{pkgNamespace},
	   				}

	   				packageMap = append(packageMap, pkg)
	   			}
	   			if err = result.Err(); err != nil {
	   				return nil, err
	   			}

	   			// var packages []*model.Package
	   			// for pkgName, versions := range packageMap {
	   			// 	pkg := model.Package{
	   			// 		Type:       pkgName,
	   			// 		Namespaces: versions,
	   			// 	}
	   			// 	for _, v := range pkg.Namespaces {
	   			// 		v.Names = &pkg
	   			// 	}
	   			// 	packages = append(packages, &pkg)
	   			// }

	   			return packageMap, nil
	   		})
	   	if err != nil {
	   		return nil, err
	   	}

	   	return result.([]*model.Package), nil */
	panic(fmt.Errorf("not implemented: Packages - packages in Neo4j backend"))
}

func matchQualifier(sb *strings.Builder, label string, key string, value string) error {
	sb.WriteString(" AND ")
	sb.WriteString(label)
	sb.WriteString(".")
	sb.WriteString(key)
	sb.WriteString(" = ")
	sb.WriteString(value)

	return nil
}

func returnQualifier(sb *strings.Builder, label, key string) error {
	sb.WriteString(", ")
	sb.WriteString(label) // not user controlled
	sb.WriteString(".")
	sb.WriteString(key) // not user controlled

	return nil
}

func (c *neo4jClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	panic(fmt.Errorf("not implemented: Sources - sources in Neo4j backend"))
}

func (c *neo4jClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if cveSpec.Year != nil && *cveSpec.Year != "" && cveSpec.CveID != nil && *cveSpec.CveID != "" {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear)-[:CveHasID]->(i:CveID) WHERE y.year = $cveYear AND i.id = $cveID RETURN y.year, i.id"

				result, err = tx.Run(query, map[string]any{"cveYear": cveSpec.Year, "cveID": strings.ToLower(*cveSpec.CveID)})
				if err != nil {
					return nil, err
				}
			} else if cveSpec.Year != nil && *cveSpec.Year != "" && cveSpec.CveID == nil {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear)-[:CveHasID]->(i:CveID) WHERE y.year = $cveYear RETURN y.year, i.id"

				result, err = tx.Run(query, map[string]any{"cveYear": cveSpec.Year})
				if err != nil {
					return nil, err
				}
			} else if cveSpec.Year == nil && cveSpec.CveID != nil && *cveSpec.CveID != "" {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear)-[:CveHasID]->(i:CveID) WHERE i.id = $cveID RETURN y.year, i.id"

				result, err = tx.Run(query, map[string]any{"cveID": strings.ToLower(*cveSpec.CveID)})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear)-[:CveHasID]->(i:CveID) RETURN y.year, i.id"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			cvesPerYear := map[string][]*model.CVEId{}
			for result.Next() {
				cveID := &model.CVEId{
					ID: result.Record().Values[1].(string),
				}
				cvesPerYear[result.Record().Values[0].(string)] = append(cvesPerYear[result.Record().Values[0].(string)], cveID)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			cves := []*model.Cve{}
			for year := range cvesPerYear {
				cve := &model.Cve{
					Year:  year,
					CveID: cvesPerYear[year],
				}
				cves = append(cves, cve)
			}

			return cves, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Cve), nil
}

func (c *neo4jClient) CveOnlyYear(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if cveSpec.Year != nil && *cveSpec.Year != "" {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear) WHERE y.year = $cveYear RETURN y.year"

				result, err = tx.Run(query, map[string]any{"cveYear": cveSpec.Year})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Cve)-[:CveIsYear]->(y:CveYear) RETURN y.year"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			cves := []*model.Cve{}
			for result.Next() {
				cve := &model.Cve{
					Year:  result.Record().Values[0].(string),
					CveID: []*model.CVEId{},
				}
				cves = append(cves, cve)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return cves, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Cve), nil
}

func (c *neo4jClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if ghsaSpec.GhsaID != nil && *ghsaSpec.GhsaID != "" {
				query := "MATCH (n:Ghsa)-[:GhsaHasID]->(i:GhsaID) WHERE i.id = $ghsaID RETURN i.id"

				result, err = tx.Run(query, map[string]any{"ghsaID": strings.ToLower(*ghsaSpec.GhsaID)})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Ghsa)-[:GhsaHasID]->(i:GhsaID) RETURN i.id"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			ghsaIds := []*model.GHSAId{}
			for result.Next() {
				ghsaId := &model.GHSAId{
					ID: result.Record().Values[0].(string),
				}
				ghsaIds = append(ghsaIds, ghsaId)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			ghsa := &model.Ghsa{
				GhsaID: ghsaIds,
			}

			return []*model.Ghsa{ghsa}, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Ghsa), nil
}

func (c *neo4jClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if osvSpec.OsvID != nil && *osvSpec.OsvID != "" {
				query := "MATCH (n:Osv)-[:OsvHasID]->(i:OsvID) WHERE i.id = $osvID RETURN i.id"

				result, err = tx.Run(query, map[string]any{"osvID": strings.ToLower(*osvSpec.OsvID)})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Osv)-[:OsvHasID]->(i:OsvID) RETURN i.id"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			osvIds := []*model.OSVId{}
			for result.Next() {
				osvId := &model.OSVId{
					ID: result.Record().Values[0].(string),
				}
				osvIds = append(osvIds, osvId)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			osv := &model.Osv{
				OsvID: osvIds,
			}

			return []*model.Osv{osv}, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Osv), nil
}

func (c *neo4jClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if artifactSpec.Algorithm != nil && *artifactSpec.Algorithm != "" && artifactSpec.Digest != nil && *artifactSpec.Digest != "" {
				query := "MATCH (n:Artifact) WHERE n.algorithm = $artifactAlgo AND n.digest = $artifactDigest RETURN n.algorithm, n.digest"

				result, err = tx.Run(query, map[string]any{"artifactAlgo": strings.ToLower(*artifactSpec.Algorithm), "artifactDigest": strings.ToLower(*artifactSpec.Digest)})
				if err != nil {
					return nil, err
				}
			} else if artifactSpec.Algorithm != nil && *artifactSpec.Algorithm != "" && artifactSpec.Digest == nil {
				query := "MATCH (n:Artifact) WHERE n.algorithm = $artifactAlgo RETURN n.algorithm, n.digest"

				result, err = tx.Run(query, map[string]any{"artifactAlgo": strings.ToLower(*artifactSpec.Algorithm)})
				if err != nil {
					return nil, err
				}
			} else if artifactSpec.Algorithm == nil && artifactSpec.Digest != nil && *artifactSpec.Digest != "" {
				query := "MATCH (n:Artifact) WHERE n.digest = $artifactDigest RETURN n.algorithm, n.digest"

				result, err = tx.Run(query, map[string]any{"artifactDigest": strings.ToLower(*artifactSpec.Digest)})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Artifact) RETURN n.algorithm, n.digest"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			artifacts := []*model.Artifact{}
			for result.Next() {
				artifact := &model.Artifact{
					Algorithm: result.Record().Values[0].(string),
					Digest:    result.Record().Values[1].(string),
				}
				artifacts = append(artifacts, artifact)
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

func (c *neo4jClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var result neo4j.Result
			var err error
			if builderSpec.URI != nil && *builderSpec.URI != "" {
				query := "MATCH (n:Builder) WHERE n.uri = $builderUri RETURN n.uri"

				result, err = tx.Run(query, map[string]any{"builderUri": builderSpec.URI})
				if err != nil {
					return nil, err
				}
			} else {
				query := "MATCH (n:Builder) RETURN n.uri"

				result, err = tx.Run(query, nil)
				if err != nil {
					return nil, err
				}
			}

			builders := []*model.Builder{}
			for result.Next() {
				builder := &model.Builder{
					URI: result.Record().Values[0].(string),
				}
				builders = append(builders, builder)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return builders, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Builder), nil
}
