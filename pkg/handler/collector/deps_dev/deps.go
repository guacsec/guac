//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deps_dev

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
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
	currentPackage  *model.PkgInputSpec
	source          *model.SourceInputSpec
	vulnerabilities []*model.OSVInputSpec
	scorecard       *model.ScorecardInputSpec
	DepPackages     []*PackageComponent
}

type depsCollector struct {
	packages    []string
	apiKey      string
	client      pb.InsightsClient
	lastChecked time.Time
	interval    time.Duration
}

func NewDepsCollector(ctx context.Context, token string, packages []string, interval time.Duration) *depsCollector {
	// Get the system certificates.
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	// Connect to the service using TLS.
	creds := credentials.NewClientTLSFromCert(sysPool, "")
	conn, err := grpc.Dial("api.deps.dev:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Insights Client.
	client := pb.NewInsightsClient(conn)

	return &depsCollector{
		packages: packages,
		apiKey:   token,
		client:   client,
		interval: interval,
	}
}

// scheme:type/namespace/name@version?qualifiers#subpath
/*
pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c

pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie

pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io

pkg:gem/jruby-launcher@1.1.2?platform=java
pkg:gem/ruby-advisory-db-check@0.12.4

pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c

pkg:golang/google.golang.org/genproto#googleapis/api/annotations

pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources
pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io%2Frelease

pkg:npm/%40angular/animation@12.3.1
pkg:npm/foobar@12.3.1

pkg:nuget/EnterpriseLibrary.Common@6.0.1304

pkg:pypi/django@1.11.1

pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25
pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed
*/
// func extractInfofromPurl(packages []string) ([]purl, error) {
// 	for _, pack := range packages {
// 		splitScheme := strings.Split(pack, ":")
// 		if len(splitScheme) > 0 {
// 			split := strings.Split(splitScheme[1], "/")
// 		}
// 	}

// }

// Store into component package and its dependencies. Marshal to json and put into document
// create processor to determine type of file (package)
// create parser to take the document and unmarshal to create package nodes with edges

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (d *depsCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	ctx = metadata.AppendToOutgoingContext(ctx, "X-DepsDev-APIKey", d.apiKey)

	for _, purl := range d.packages {
		err := d.fetchDependencies(ctx, purl, docChannel)
		if err != nil {
			return err
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

	component.currentPackage = packageInput

	versionReq := &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{
			System:  parseSystem(packageInput.Type),
			Name:    packageInput.Name,
			Version: *packageInput.Version,
		},
	}

	version, err := d.client.GetVersion(ctx, versionReq)
	if err != nil {
		log.Fatal(err)
	}

	for _, link := range version.Links {
		if link.Label == "REPO" {
			src, err := helpers.VcsToSrc(link.Url)
			if err != nil {
				continue
			}
			component.source = src

			projectReq := &pb.GetProjectRequest{
				ProjectKey: &pb.ProjectKey{
					Id: link.Label,
				},
			}

			project, err := d.client.GetProject(ctx, projectReq)
			if err != nil {
				log.Fatal(err)
			}
			if project.Scorecard != nil {
				component.scorecard.AggregateScore = float64(project.Scorecard.OverallScore)
				component.scorecard.ScorecardCommit = project.Scorecard.Scorecard.Commit
				component.scorecard.ScorecardVersion = project.Scorecard.Scorecard.Version
				component.scorecard.TimeScanned = project.Scorecard.Date.AsTime().UTC()
				component.scorecard.Origin = DepsCollector
				component.scorecard.Collector = DepsCollector
				inputChecks := []model.ScorecardCheckInputSpec{}
				for _, check := range project.Scorecard.Checks {
					inputCheck := model.ScorecardCheckInputSpec{
						Check: check.Name,
						Score: int(check.Score),
					}
					inputChecks = append(inputChecks, inputCheck)
				}
				component.scorecard.Checks = inputChecks
			}
		}
	}

	vulnerabilities := []*model.OSVInputSpec{}
	for _, vuln := range version.AdvisoryKeys {
		advisory, err := d.client.GetAdvisory()
		if e
		vuln := model.OSVInputSpec{
			OsvId: vuln.Id,
		}
		vulnerabilities = append(vulnerabilities, &vuln)
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

	packageReq := &pb.GetPackageRequest{
		VersionKey: &pb.PackageKey{
			System:  parseSystem(packageInput.Type),
			Name:    packageInput.Name,
			Version: *packageInput.Version,
		},
	}

	advisoryReq := &pb.GetAdvisoryRequest{
		VersionKey: &pb.AdvisoryKey{
			System:  parseSystem(packageInput.Type),
			Name:    packageInput.Name,
			Version: *packageInput.Version,
		},
	}

	versionReq := &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{
			System:  parseSystem(packageInput.Type),
			Name:    packageInput.Name,
			Version: *packageInput.Version,
		},
	}

	req := &pb.VersionsRequest{
		PackageKey: &pb.PackageKey{
			System: sys,
			Name:   pkg,
		},
	}

	deps, err := d.client.GetDependencies(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	projects, err := d.client.GetProject()

	packs, err := d.client.GetPackage()

	
	version, err := d.client.GetVersion()

	vulnKeys := version.AdvisoryKeys[0].Id
	source := version.Links[0].Url

	for _, node := range deps.Nodes {
		// pkg:pypi/django@1.11.1
		purl := "pkg:" + pack.system + "/" + node.VersionKey.Name + "@" + node.VersionKey.Version
		component.DepPackages = append(component.DepPackages, &certifier.Component{Package: assembler.PackageNode{Purl: purl}})
	}

	blob, err := json.Marshal(component)
	if err != nil {
		return err
	}

	doc := &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector: string(DepsCollector),
			Source:    "deps.dev",
		},
	}

	docChannel <- doc

	return nil
}

// parseSystem returns the pb.System value represented by the argument string.
func parseSystem(name string) pb.System {
	sys, ok := pb.System_value["SYSTEM_"+strings.ToUpper(name)]
	if !ok {
		log.Fatalf("unknown Insights system %q", name)
	}
	return pb.System(sys)
}

// defaultVersion returns the default version identifier for the package.
func defaultVersion(ctx context.Context, client pb.InsightsClient, sys pb.System, pkg string) string {
	// Make an RPC Request. The returned result is a stream of
	// VersionsResponse structs.
	req := &pb.VersionsRequest{
		PackageKey: &pb.PackageKey{
			System: sys,
			Name:   pkg,
		},
	}
	stream, err := client.Versions(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	// Drain the stream until we hit EOF.
	def := ""
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		for _, version := range resp.Versions {
			if version.IsDefault {
				def = version.VersionKey.Version // Don't return here; continue to drain the stream.
			}
		}
	}
	if def == "" {
		log.Fatalf("no default version found for package %s", pkg)
	}
	return def
}

// Type returns the collector type
func (d *depsCollector) Type() string {
	return DepsCollector
}

/*
import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/guacsec/guac/pkg/handler/collector/deps_dev/internal"
)

const usageMessage = `Usage:

	deplist <system> <package> [<version>]

Where system, which is case-insensitive, is one of

	CARGO
	GO
	MAVEN
	NPM
	PYPI

and package and version have the usual string representations.

If no version is specified, deplist reports on the default version for
the package.

The API key is a mandatory token used for authentication. It may be
provided by the api_key flag or the INSIGHTS_API_KEY environment
variable. See this repository's README.md for instructions.
`

var (
	addrFlag   = flag.String("addr", "api.deps.dev:443", "`address` to dial")
	apiKeyFlag = flag.String("api_key", "", "deps.dev API `key` (no default)")
)

func usage() {
	fmt.Fprintln(os.Stderr, usageMessage)
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	// Initialize.
	log.SetFlags(0)
	log.SetPrefix("deplist: ")
	flag.Usage = usage
	flag.Parse()

	// Grab the system and package. Version comes later after we have a gRPC client.
	if len(flag.Args()) != 2 && len(flag.Args()) != 3 {
		usage()
	}
	sys := parseSystem(flag.Arg(0))
	pkg := flag.Arg(1)

	// Make sure we have a session ID.
	apiKey := *apiKeyFlag
	if apiKey == "" {
		apiKey = os.Getenv("INSIGHTS_API_KEY")
		if apiKey == "" {
			log.Println("Missing API key.")
			usage()
		}
	}

	// Get the system certificates.
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	// Connect to the service using TLS.
	creds := credentials.NewClientTLSFromCert(sysPool, "")
	conn, err := grpc.Dial(*addrFlag, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}

	// Create a new Insights Client.
	client := pb.NewInsightsClient(conn)

	// Create a context that attaches the API key as a gRPC header.
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "X-DepsDev-APIKey", apiKey)

	// If the user didn't specify a version, we need to find one.
	var version string
	if len(flag.Args()) == 3 {
		version = flag.Arg(2)
	} else {
		version = defaultVersion(ctx, client, sys, pkg)
	}

	// Make an RPC Request. The returned result is a stream of
	// DependenciesResponse structs.
	req := &pb.DependenciesRequest{
		VersionKey: &pb.VersionKey{
			System:  sys,
			Name:    pkg,
			Version: version,
		},
	}
	stream, err := client.Dependencies(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	// Drain the stream until we hit EOF.
	var deps []string
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		for _, node := range resp.Nodes {
			deps = append(deps, fmt.Sprintf("%s %s", node.VersionKey.Name, node.VersionKey.Version))
		}
	}

	// Sort and print the output. The zeroth entry is the root, so leave it and sort the rest.
	sort.Strings(deps[1:])
	for _, dep := range deps {
		fmt.Println(dep)
	}
}

// parseSystem returns the pb.System value represented by the argument string.
func parseSystem(name string) pb.System {
	sys, ok := pb.System_value["SYSTEM_"+strings.ToUpper(name)]
	if !ok {
		log.Fatalf("unknown Insights system %q", name)
	}
	return pb.System(sys)
}

// defaultVersion returns the default version identifier for the package.
func defaultVersion(ctx context.Context, client pb.InsightsClient, sys pb.System, pkg string) string {
	// Make an RPC Request. The returned result is a stream of
	// VersionsResponse structs.
	req := &pb.VersionsRequest{
		PackageKey: &pb.PackageKey{
			System: sys,
			Name:   pkg,
		},
	}
	stream, err := client.Versions(ctx, req)
	if err != nil {
		log.Fatal(err)
	}

	// Drain the stream until we hit EOF.
	def := ""
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		for _, version := range resp.Versions {
			if version.IsDefault {
				def = version.VersionKey.Version // Don't return here; continue to drain the stream.
			}
		}
	}
	if def == "" {
		log.Fatalf("no default version found for package %s", pkg)
	}
	return def
} */
