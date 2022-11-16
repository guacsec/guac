//
// Copyright 2022 The GUAC Authors.
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

package cyclonedx

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type cyclonedxParser struct {
	doc           *processor.Document
	rootComponent component
	pkgMap        map[string]*component
}

type component struct {
	curPackage  assembler.PackageNode
	depPackages []*component
}

func NewCycloneDXParser() common.DocumentParser {
	return &cyclonedxParser{
		rootComponent: component{},
		pkgMap:        map[string]*component{},
	}
}

func (c *cyclonedxParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	nodes = append(nodes, c.rootComponent.curPackage)
	for _, p := range c.rootComponent.depPackages {
		nodes = append(nodes, p.curPackage)
	}
	return nodes
}

func addEdges(curPkg component, edges *[]assembler.GuacEdge) {
	// this could happen if we image purl creation fails for rootPackage
	// we need better solution to support different image name formats in SBOM
	if curPkg.curPackage.Name == "" {
		return
	}
	for _, d := range curPkg.depPackages {
		*edges = append(*edges, assembler.DependsOnEdge{PackageNode: curPkg.curPackage, PackageDependency: d.curPackage})
		addEdges(*d, edges)
	}
}

// Parse breaks out the document into the graph components
func (c *cyclonedxParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	cdxBom, err := parseCycloneDXBOM(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse cyclonedx BOM: %w", err)
	}
	c.addRootPackage(cdxBom)
	c.addPackages(cdxBom)

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *cyclonedxParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

func (c *cyclonedxParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	addEdges(c.rootComponent, &edges)
	return edges
}

func (c *cyclonedxParser) addRootPackage(cdxBom *cdx.BOM) {
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	if cdxBom.Metadata.Component != nil {
		rootPackage := assembler.PackageNode{}
		rootPackage.Name = cdxBom.Metadata.Component.Name
		// rootPackage.CPEs = nil
		rootPackage.NodeData = *assembler.NewObjectMetadata(c.doc.SourceInformation)
		if cdxBom.Metadata.Component.PackageURL != "" {
			rootPackage.Purl = cdxBom.Metadata.Component.PackageURL
			rootPackage.Version = cdxBom.Metadata.Component.Version
			rootPackage.Tags = []string{string(cdxBom.Metadata.Component.Type)}
		} else {
			splitImage := strings.Split(cdxBom.Metadata.Component.Name, "/")
			if len(splitImage) == 3 {
				rootPackage.Purl = "pkg:oci/" + splitImage[2] + "?repository_url=" + splitImage[0] + "/" + splitImage[1]
				rootPackage.Version = cdxBom.Metadata.Component.Version
				rootPackage.Digest = append(rootPackage.Digest, cdxBom.Metadata.Component.Version)
				rootPackage.Tags = []string{"CONTAINER"}
			}
		}
		c.rootComponent = component{
			curPackage:  rootPackage,
			depPackages: []*component{},
		}
	}
}

func (c *cyclonedxParser) addPackages(cdxBom *cdx.BOM) {
	for _, comp := range *cdxBom.Components {
		curPkg := assembler.PackageNode{
			Name: comp.Name,
			// Digest: []string{comp.Version},
			Purl:     comp.PackageURL,
			Version:  comp.Version,
			NodeData: *assembler.NewObjectMetadata(c.doc.SourceInformation),
		}
		if comp.CPE != "" {
			curPkg.CPEs = []string{comp.CPE}
		}
		parentPkg := component{
			curPackage:  curPkg,
			depPackages: []*component{},
		}
		c.rootComponent.depPackages = append(c.rootComponent.depPackages, &parentPkg)
		c.pkgMap[comp.BOMRef] = &parentPkg
	}

	if cdxBom.Dependencies == nil {
		return
	}
	for _, deps := range *cdxBom.Dependencies {
		currPkg, found := c.pkgMap[deps.Ref]
		if !found {
			continue
		}
		for _, depPkg := range *deps.Dependencies {
			if depPkg, exist := c.pkgMap[depPkg]; exist {
				currPkg.depPackages = append(currPkg.depPackages, depPkg)
			}
		}
	}
}

func parseCycloneDXBOM(d []byte) (*cdx.BOM, error) {
	bom := cdx.BOM{}
	if err := json.Unmarshal(d, &bom); err != nil {
		return nil, err
	}
	return &bom, nil
}
