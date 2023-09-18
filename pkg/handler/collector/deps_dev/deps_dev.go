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
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	pb "github.com/guacsec/guac/pkg/handler/collector/deps_dev/internal"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DepsCollector = "deps.dev"
	goUpperCase   = "GO"
	golang        = "golang"
	maven         = "maven"
	sourceRepo    = "SOURCE_REPO"
)

type IsDepPackage struct {
	CurrentPackageInput *model.PkgInputSpec
	DepPackageInput     *model.PkgInputSpec
	IsDependency        *model.IsDependencyInputSpec
}

type PackageComponent struct {
	CurrentPackage *model.PkgInputSpec
	Source         *model.SourceInputSpec
	Scorecard      *model.ScorecardInputSpec
	IsDepPackages  []*IsDepPackage
	DepPackages    []*PackageComponent
	UpdateTime     time.Time
}

type depsCollector struct {
	collectDataSource datasource.CollectSource
	client            pb.InsightsClient
	poll              bool
	interval          time.Duration
	checkedPurls      map[string]*PackageComponent
	ingestedSource    map[string]*model.SourceInputSpec
}

func NewDepsCollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration) (*depsCollector, error) {
	// Get the system certificates.
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert: %w", err)
	}

	// Connect to the service using TLS.
	creds := credentials.NewClientTLSFromCert(sysPool, "")
	conn, err := grpc.Dial("api.deps.dev:443",
		grpc.WithTransportCredentials(creds),
		grpc.WithUserAgent(version.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to api.deps.dev: %w", err)
	}

	// Create a new Insights Client.
	client := pb.NewInsightsClient(conn)

	return &depsCollector{
		collectDataSource: collectDataSource,
		client:            client,
		poll:              poll,
		interval:          interval,
		checkedPurls:      map[string]*PackageComponent{},
		ingestedSource:    map[string]*model.SourceInputSpec{},
	}, nil
}

// RetrieveArtifacts get the metadata from deps.dev based on the purl provided
func (d *depsCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if d.poll {
		for {
			if err := d.populatePurls(ctx, docChannel); err != nil {
				return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
			}
			select {
			// If the context has been canceled it contains an err which we can throw.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(d.interval):
			}
		}
	} else {
		if err := d.populatePurls(ctx, docChannel); err != nil {
			return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
		}
	}

	return nil
}

func (d *depsCollector) populatePurls(ctx context.Context, docChannel chan<- *processor.Document) error {
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

	// check if top level purl has already been queried
	if _, ok := d.checkedPurls[purl]; ok {
		logger.Infof("purl %s already queried", purl)
		return nil
	}

	packageInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		logger.Infof("failed to parse purl to pkg: %s", purl)
		return nil
	}

	// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
	if *packageInput.Version == "" {
		logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
		return nil
	}

	component.CurrentPackage = packageInput

	err = d.collectAdditionalMetadata(ctx, packageInput.Type, packageInput.Namespace, packageInput.Name, packageInput.Version, component)
	if err != nil {
		logger.Debugf("failed to get additional metadata for package: %s, err: %v", purl, err)
	}

	// Make an RPC Request. The returned result is a stream of
	// DependenciesResponse structs.
	versionKey, err := getVersionKey(packageInput.Type, packageInput.Namespace, packageInput.Name, packageInput.Version)
	if err != nil {
		logger.Infof("failed to getVersionKey with the following error: %v", err)
		return nil
	}

	dependenciesReq := &pb.GetDependenciesRequest{
		VersionKey: versionKey,
	}

	deps, err := d.client.GetDependencies(ctx, dependenciesReq)
	if err != nil {
		logger.Debugf("failed to get dependencies", err)
		return nil
	}

	dependencyNodes := []*PackageComponent{}

	// append the i=0 node as the root node of the graph
	dependencyNodes = append(dependencyNodes, component)

	for i, node := range deps.Nodes {
		// the nodes of the dependency graph. The first node is the root of the graph, which is captured above so skip.
		if i == 0 {
			continue
		}

		depComponent := &PackageComponent{}

		pkgtype := ""
		if node.VersionKey.System.String() == goUpperCase {
			pkgtype = golang
		} else {
			pkgtype = strings.ToLower(node.VersionKey.System.String())
		}

		depPurl := "pkg:" + pkgtype + "/" + node.VersionKey.Name + "@" + node.VersionKey.Version
		depPackageInput, err := helpers.PurlToPkg(depPurl)
		if err != nil {
			logger.Infof("unable to parse purl: %v, error: %v", depPurl, err)
			continue
		}
		// check if dependent package purl has already been queried. If found, append to the list of dependent packages for top level package
		if foundDepVal, ok := d.checkedPurls[depPurl]; ok {
			// if found, return the source as nothing as it has already been ingested once
			foundDepVal.Source = nil
			logger.Debugf("dependant package purl %s already queried", depPurl)

			dependencyNodes = append(dependencyNodes, foundDepVal)
			continue
		}
		depComponent.CurrentPackage = depPackageInput
		err = d.collectAdditionalMetadata(ctx, depPackageInput.Type, depPackageInput.Namespace, depPackageInput.Name, depPackageInput.Version, depComponent)
		if err != nil {
			logger.Debugf("failed to get additional metadata for package: %s, err: %v", depPurl, err)
		}
		dependencyNodes = append(dependencyNodes, depComponent)
		d.checkedPurls[depPurl] = depComponent
	}

	component.DepPackages = append(component.DepPackages, dependencyNodes[1:]...)

	for _, edge := range deps.Edges {
		isDep := &model.IsDependencyInputSpec{
			VersionRange:   edge.Requirement,
			DependencyType: model.DependencyTypeDirect,
			Justification:  "dependency data collected via deps.dev",
		}
		foundDepPackage := &IsDepPackage{
			CurrentPackageInput: dependencyNodes[edge.FromNode].CurrentPackage,
			DepPackageInput:     dependencyNodes[edge.ToNode].CurrentPackage,
			IsDependency:        isDep,
		}
		component.IsDepPackages = append(component.IsDepPackages, foundDepPackage)
	}

	logger.Infof("obtained additional metadata for package: %s", purl)

	d.checkedPurls[purl] = component

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

func (d *depsCollector) collectAdditionalMetadata(ctx context.Context, pkgType string, namespace *string, name string, version *string, pkgComponent *PackageComponent) error {
	logger := logging.FromContext(ctx)

	versionKey, err := getVersionKey(pkgType, namespace, name, version)
	if err != nil {
		return fmt.Errorf("failed to getVersionKey with the following error: %w", err)
	}
	versionReq := &pb.GetVersionRequest{
		VersionKey: versionKey,
	}

	versionResponse, err := d.client.GetVersion(ctx, versionReq)
	if err != nil {
		return fmt.Errorf("failed to get version information: err: %w", err)
	}

	for _, link := range versionResponse.Links {
		if link.Label == sourceRepo {
			src, err := helpers.VcsToSrc(link.Url)
			if err != nil {
				logger.Infof("unable to parse source url: %v, error: %v", link.Url, err)
				continue
			}

			// check if source has already been ingest for this package (without version), if not add source to be ingest for hasSourceAt
			// HasSourceAt is done at the pkgName level for all entries from deps.dev as it does not specify a tag or commit for each version
			// of the package being ingested
			purlWithoutVersion := "pkg:" + pkgType + "/" + strings.TrimSuffix(*namespace, "/") + "/" + name
			if _, ok := d.ingestedSource[purlWithoutVersion]; !ok {
				pkgComponent.Source = src
				d.ingestedSource[purlWithoutVersion] = src
			}

			projectReq := &pb.GetProjectRequest{
				ProjectKey: &pb.ProjectKey{
					Id: strings.TrimSuffix(src.Namespace, "/") + "/" + src.Name,
				},
			}

			project, err := d.client.GetProject(ctx, projectReq)
			if err != nil {
				logger.Debugf("unable to get project for: %v, error: %v", projectReq.ProjectKey.Id, err)
				continue
			}
			if project.Scorecard != nil {
				pkgComponent.Scorecard = &model.ScorecardInputSpec{}
				pkgComponent.Scorecard.AggregateScore = float64(project.Scorecard.OverallScore)
				pkgComponent.Scorecard.ScorecardCommit = project.Scorecard.Scorecard.Commit
				pkgComponent.Scorecard.ScorecardVersion = project.Scorecard.Scorecard.Version
				pkgComponent.Scorecard.TimeScanned = project.Scorecard.Date.AsTime().UTC()
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

	// add time when data was obtained
	pkgComponent.UpdateTime = time.Now().UTC()

	return nil
}

func getVersionKey(pkgType string, namespace *string, name string, version *string) (*pb.VersionKey, error) {
	queryName := ""
	if pkgType != maven {
		if namespace != nil && *namespace != "" {
			queryName = strings.TrimSuffix(*namespace, "/") + "/" + name
		} else {
			queryName = name
		}
	} else {
		if namespace != nil && *namespace != "" {
			queryName = strings.TrimSuffix(*namespace, ":") + ":" + name
		} else {
			queryName = name
		}
	}

	sys, err := parseSystem(pkgType)
	if err != nil {
		return nil, err
	}
	versionKey := &pb.VersionKey{
		System:  sys,
		Name:    queryName,
		Version: *version,
	}
	return versionKey, nil
}

// parseSystem returns the pb.System value represented by the argument string.
func parseSystem(name string) (pb.System, error) {
	systemType := ""
	if name == golang {
		systemType = goUpperCase
	} else {
		systemType = strings.ToUpper(name)
	}
	sys, ok := pb.System_value[systemType]
	if !ok {
		return pb.System_SYSTEM_UNSPECIFIED, fmt.Errorf("unknown Insights system %q", name)
	}
	return pb.System(sys), nil
}

// Type returns the collector type
func (d *depsCollector) Type() string {
	return DepsCollector
}
