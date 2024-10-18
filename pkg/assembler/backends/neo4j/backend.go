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

package neo4j

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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
	status        string = "status"
	statement     string = "statement"
	statusNotes   string = "statusNotes"
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

func init() {
	backends.Register("neo4j", getBackend)
}

func getBackend(_ context.Context, args backends.BackendArgs) (backends.Backend, error) {
	config, ok := args.(*Neo4jConfig)
	if !ok {
		return nil, fmt.Errorf("failed to assert neo4j config from backend args")
	}
	token := neo4j.BasicAuth(config.User, config.Pass, config.Realm)
	driver, err := neo4j.NewDriver(config.DBAddr, token)
	if err != nil {
		return nil, err
	}

	if err = driver.VerifyConnectivity(); err != nil {
		driver.Close()
		return nil, err
	}
	client := &neo4jClient{driver: driver}
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

func (c *neo4jClient) Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error) {
	panic(fmt.Errorf("not implemented: Licenses"))
}

func (c *neo4jClient) LicenseList(ctx context.Context, licenseSpec model.LicenseSpec, after *string, first *int) (*model.LicenseConnection, error) {
	panic(fmt.Errorf("not implemented: LicenseList"))
}

func (c *neo4jClient) IngestLicense(ctx context.Context, license *model.IDorLicenseInput) (string, error) {
	panic(fmt.Errorf("not implemented: IngestLicense"))
}
func (c *neo4jClient) IngestLicenses(ctx context.Context, licenses []*model.IDorLicenseInput) ([]string, error) {
	panic(fmt.Errorf("not implemented: IngestLicenses"))
}

func (c *neo4jClient) CertifyLegalList(ctx context.Context, certifyLegalSpec model.CertifyLegalSpec, after *string, first *int) (*model.CertifyLegalConnection, error) {
	panic(fmt.Errorf("not implemented: CertifyLegalList"))
}

func (c *neo4jClient) CertifyLegal(ctx context.Context, certifyLegalSpec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {
	panic(fmt.Errorf("not implemented: CertifyLegal"))
}
func (c *neo4jClient) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, certifyLegal *model.CertifyLegalInputSpec) (string, error) {
	panic(fmt.Errorf("not implemented: IngestCertifyLegal"))
}
func (c *neo4jClient) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error) {
	panic(fmt.Errorf("not implemented: IngestCertifyLegals"))
}
