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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *neo4jClient) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	return []model.PackageSourceOrArtifact{}, fmt.Errorf("not implemented: FindSoftware")
}

func (c *neo4jClient) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

func (c *neo4jClient) QueryPackagesListForScan(ctx context.Context, pkgIDs []string, after *string, first *int) (*model.PackageConnection, error) {
	return nil, fmt.Errorf("not implemented: QueryPackagesListForScan")
}

func (c *neo4jClient) FindPackagesThatNeedScanning(ctx context.Context, queryType model.QueryType, lastScan *int) ([]string, error) {
	return nil, fmt.Errorf("not implemented: FindPackagesThatNeedScanning")
}

func (c *neo4jClient) BatchQueryPkgIDCertifyVuln(ctx context.Context, pkgIDs []string) ([]*model.CertifyVuln, error) {
	return nil, fmt.Errorf("not implemented: BatchQueryPkgIDCertifyVuln")
}

func (c *neo4jClient) BatchQueryPkgIDCertifyLegal(ctx context.Context, pkgIDs []string) ([]*model.CertifyLegal, error) {
	return nil, fmt.Errorf("not implemented: BatchQueryPkgIDCertifyLegal")
}

func (c *neo4jClient) BatchQuerySubjectPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {
	return nil, fmt.Errorf("not implemented: BatchQuerySubjectPkgDependency")
}

func (c *neo4jClient) BatchQueryDepPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {
	return nil, fmt.Errorf("not implemented: BatchQueryDepPkgDependency")
}
