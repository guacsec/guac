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

package deps_dev

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	pb "github.com/guacsec/guac/pkg/handler/collector/deps_dev/internal"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	DepsCollector = "deps.dev"
)

type PackageComponent struct {
	CurrentPackage  *model.PkgInputSpec
	Source          *model.SourceInputSpec
	Vulnerabilities []*model.OSVInputSpec
	Scorecard       *model.ScorecardInputSpec
	DepPackages     []*PackageComponent
	UpdateTime      time.Time
}

type depsCollector struct {
	collectDataSource datasource.CollectSource
	apiKey            string
	client            pb.InsightsClient
}

func NewDepsCollector(ctx context.Context, token string, collectDataSource datasource.CollectSource) (*depsCollector, error) {
	// Get the system certificates.
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert: %w", err)
	}

	// Connect to the service using TLS.
	creds := credentials.NewClientTLSFromCert(sysPool, "")
	conn, err := grpc.Dial("api.deps.dev:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to api.deps.dev: %w", err)
	}

	// Create a new Insights Client.
	client := pb.NewInsightsClient(conn)

	return &depsCollector{
		collectDataSource: collectDataSource,
		apiKey:            token,
		client:            client,
	}, nil
}

// RetrieveArtifacts get the metadata from deps.dev based on the purl provided
func (d *depsCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	ctx = metadata.AppendToOutgoingContext(ctx, "X-DepsDev-APIKey", d.apiKey)

	ds, err := d.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, purl := range ds.PurlDataSources {
		err := d.fetchDependencies(ctx, purl.Value, docChannel)
		if err != nil {
			return fmt.Errorf("failed to fetch dependencies: %w", err)
		}
	}

	return nil
}

func (d *depsCollector) fetchDependencies(ctx context.Context, purl string, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	component := &PackageComponent{}
	packageInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return err
	}

	// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
	if *packageInput.Version == "" {
		logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
		return nil
	}

	component.CurrentPackage = packageInput

	err = d.collectAdditionalMetadata(ctx, packageInput.Type, packageInput.Name, *packageInput.Version, component)
	if err != nil {
		logger.Errorf("failed to get additional metadata for package: %s, err: %w", purl, err)
	}

	// Make an RPC Request. The returned result is a stream of
	// DependenciesResponse structs.
	dependenciesReq := &pb.GetDependenciesRequest{
		VersionKey: &pb.VersionKey{
			System:  parseSystem(packageInput.Type),
			Name:    packageInput.Name,
			Version: *packageInput.Version,
		},
	}

	deps, err := d.client.GetDependencies(ctx, dependenciesReq)
	if err != nil {
		log.Fatal(err)
	}

	for i, node := range deps.Nodes {
		// the nodes of the dependency graph. The first node is the root of the graph, which is captured above so skip.
		if i == 0 {
			continue
		}
		depComponent := &PackageComponent{}

		depPackageInput := &model.PkgInputSpec{
			Type:       strings.ToLower(node.VersionKey.System.String()),
			Namespace:  ptrfrom.String(""),
			Name:       node.VersionKey.Name,
			Version:    &node.VersionKey.Version,
			Qualifiers: []model.PackageQualifierInputSpec{},
			Subpath:    ptrfrom.String(""),
		}

		depComponent.CurrentPackage = depPackageInput

		err = d.collectAdditionalMetadata(ctx, depPackageInput.Type, depPackageInput.Name, *depPackageInput.Version, depComponent)
		if err != nil {
			logger.Errorf("failed to get additional metadata for package: %s, err: %w", purl, err)
		}
		component.DepPackages = append(component.DepPackages, depComponent)
	}

	blob, err := json.Marshal(component)
	if err != nil {
		return err
	}

	doc := &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentDepsDev,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: DepsCollector,
			Source:    DepsCollector,
		},
	}
	docChannel <- doc

	return nil
}

func (d *depsCollector) collectAdditionalMetadata(ctx context.Context, system, name, version string, pkgComponent *PackageComponent) error {
	versionReq := &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{
			System:  parseSystem(system),
			Name:    name,
			Version: version,
		},
	}

	versionResponse, err := d.client.GetVersion(ctx, versionReq)
	if err != nil {
		return err
	}

	for _, link := range versionResponse.Links {
		if link.Label == "SOURCE_REPO" {
			src, err := helpers.VcsToSrc(link.Url)
			if err != nil {
				continue
			}
			pkgComponent.Source = src

			projectReq := &pb.GetProjectRequest{
				ProjectKey: &pb.ProjectKey{
					Id: src.Namespace + "/" + src.Name,
				},
			}

			project, err := d.client.GetProject(ctx, projectReq)
			if err != nil {
				continue
			}
			if project.Scorecard != nil {
				pkgComponent.Scorecard = &model.ScorecardInputSpec{}
				pkgComponent.Scorecard.AggregateScore = float64(project.Scorecard.OverallScore)
				pkgComponent.Scorecard.ScorecardCommit = project.Scorecard.Scorecard.Commit
				pkgComponent.Scorecard.ScorecardVersion = project.Scorecard.Scorecard.Version
				pkgComponent.Scorecard.TimeScanned = project.Scorecard.Date.AsTime().UTC()
				pkgComponent.Scorecard.Origin = DepsCollector
				pkgComponent.Scorecard.Collector = DepsCollector
				inputChecks := []model.ScorecardCheckInputSpec{}
				for _, check := range project.Scorecard.Checks {
					inputCheck := model.ScorecardCheckInputSpec{
						Check: check.Name,
						Score: int(check.Score),
					}
					inputChecks = append(inputChecks, inputCheck)
				}
				pkgComponent.Scorecard.Checks = inputChecks
			}
		}
	}

	vulnerabilities := []*model.OSVInputSpec{}
	for _, vuln := range versionResponse.AdvisoryKeys {
		osv := model.OSVInputSpec{
			OsvId: vuln.Id,
		}
		vulnerabilities = append(vulnerabilities, &osv)
	}
	pkgComponent.Vulnerabilities = append(pkgComponent.Vulnerabilities, vulnerabilities...)
	// add time when data was obtained
	pkgComponent.UpdateTime = time.Now().UTC()

	return nil
}

// parseSystem returns the pb.System value represented by the argument string.
func parseSystem(name string) pb.System {
	sys, ok := pb.System_value[strings.ToUpper(name)]
	if !ok {
		log.Fatalf("unknown Insights system %q", name)
	}
	return pb.System(sys)
}

// Type returns the collector type
func (d *depsCollector) Type() string {
	return DepsCollector
}
