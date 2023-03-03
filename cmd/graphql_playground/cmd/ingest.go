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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func ingestData(port int) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	// ensure server is up
	time.Sleep(1 * time.Second)

	// Create a http client to send the mutation through
	url := fmt.Sprintf("http://localhost:%d/query", port)
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(url, &httpClient)

	logger.Infof("Ingesting test data into backend server")
	ingestScorecards(ctx, gqlclient)
	ingestDependency(ctx, gqlclient)
	ingestOccurrence(ctx, gqlclient)
	logger.Infof("Finished ingesting test data into backend server")
}

func ingestScorecards(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	tag := "v2.12.0"
	source := model.SourceInputSpec{
		Type:      "git",
		Namespace: "github",
		Name:      "github.com/tensorflow/tensorflow",
		Tag:       &tag,
	}
	checks := []model.ScorecardCheckInputSpec{
		{Check: "Binary_Artifacts", Score: 4},
		{Check: "Branch_Protection", Score: 3},
		{Check: "Code_Review", Score: 2},
		{Check: "Contributors", Score: 1},
	}
	scorecard := model.ScorecardInputSpec{
		Checks:           checks,
		AggregateScore:   2.9,
		TimeScanned:      time.Now(),
		ScorecardVersion: "v4.10.2",
		ScorecardCommit:  "5e6a521",
		Origin:           "Demo ingestion",
		Collector:        "Demo ingestion",
	}
	resp, err := model.Scorecard(context.Background(), client, source, scorecard)
	if err != nil {
		// TODO(mihaimaruseac): Panic or just error and continue?
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", resp)
}

func ingestDependency(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	ns := "ubuntu"
	version := "1.19.0.4"
	pkg := model.PkgInputSpec{
		Type:       "deb",
		Namespace:  &ns,
		Name:       "dpkg",
		Version:    &version,
		Qualifiers: []model.PackageQualifierInputSpec{{Key: "arch", Value: "amd64"}},
	}
	depns := "openssl.org"
	depPkg := model.PkgInputSpec{
		Type:      "conan",
		Namespace: &depns,
		Name:      "openssl",
	}
	dependency := model.IsDependencyInputSpec{
		VersionRange:  "3.0.3",
		Justification: "deb: part of SBOM - openssl",
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	resp, err := model.IsDependency(context.Background(), client, pkg, depPkg, dependency)
	if err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", resp)

	ns = "smartentry"
	pkg = model.PkgInputSpec{
		Type:      "docker",
		Namespace: &ns,
		Name:      "debian",
	}
	dependency = model.IsDependencyInputSpec{
		VersionRange:  "3.0.3",
		Justification: "docker: part of SBOM - openssl",
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	resp, err = model.IsDependency(context.Background(), client, pkg, depPkg, dependency)
	if err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", resp)
}

func ingestOccurrence(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	ns := "openssl.org"
	version := "3.0.3"
	pkg := model.PkgInputSpec{
		Type:       "conan",
		Namespace:  &ns,
		Name:       "openssl",
		Version:    &version,
		Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
	}
	occurrence := model.IsOccurrenceSpecInputSpec{
		Justification: "this artifact is an occurrence of this package",
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	respPkg, err := model.IsOccurrencePkg(context.Background(), client, &pkg, model.ArtifactInputSpec{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, occurrence)
	if err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", respPkg)

	selectedTag := "v0.0.1"
	src := model.SourceInputSpec{
		Type:      "git",
		Namespace: "github",
		Name:      "github.com/guacsec/guac",
		Tag:       &selectedTag,
	}
	occurrence = model.IsOccurrenceSpecInputSpec{
		Justification: "this artifact is an occurrence of this source",
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	respSrc, err := model.IsOccurrenceSrc(context.Background(), client, &src, model.ArtifactInputSpec{Digest: "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf", Algorithm: "sha256"}, occurrence)
	if err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", respSrc)
}
