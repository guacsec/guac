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
	"encoding/xml"
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

// TODO(bulldozer): replace with GetPredicates
// func (c *cyclonedxParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
// 	nodes := []assembler.GuacNode{}
// 	nodes = append(nodes, c.rootComponent.curPackage)
// 	for _, p := range c.rootComponent.depPackages {
// 		nodes = append(nodes, p.curPackage)
// 	}
// 	return nodes
// }

func addEdges(curPkg component, edges *[]assembler.GuacEdge, visited map[string]bool) {
	// this could happen if we image purl creation fails for rootPackage
	// we need better solution to support different image name formats in SBOM
	if curPkg.curPackage.Name == "" {
		return
	}
	// Exit the function if the package has already been visited
	if visited[curPkg.curPackage.Name] {
		return
	}
	visited[curPkg.curPackage.Name] = true

	for _, dep := range curPkg.depPackages {
		// Append the dependency edge to the edges slice
		*edges = append(*edges, assembler.DependsOnEdge{PackageNode: curPkg.curPackage, PackageDependency: dep.curPackage})

		// Recursively call addEdges for each dependent package
		addEdges(*dep, edges, visited)
	}
}

// Parse breaks out the document into the graph components
func (c *cyclonedxParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	cdxBom, err := parseCycloneDXBOM(doc)
	if err != nil {
		return fmt.Errorf("failed to parse cyclonedx BOM: %w", err)
	}
	c.addRootPackage(cdxBom)
	c.addPackages(cdxBom)

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *cyclonedxParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

// TODO(bulldozer): replace with GetPredicates
// func (c *cyclonedxParser) CreateEdges(ctx context.Context, foundIdentities []common.TrustInformation) []assembler.GuacEdge {
// 	edges := []assembler.GuacEdge{}
// 	visited := make(map[string]bool)
// 	addEdges(c.rootComponent, &edges, visited)
// 	return edges
// }

func (c *cyclonedxParser) addRootPackage(cdxBom *cdx.BOM) {
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	if cdxBom.Metadata.Component != nil {
		rootPackage := assembler.PackageNode{}
		rootPackage.Name = cdxBom.Metadata.Component.Name
		rootPackage.NodeData = *assembler.NewObjectMetadata(c.doc.SourceInformation)
		if cdxBom.Metadata.Component.PackageURL != "" {
			rootPackage.Purl = cdxBom.Metadata.Component.PackageURL
			rootPackage.Version = cdxBom.Metadata.Component.Version
			rootPackage.Tags = []string{string(cdxBom.Metadata.Component.Type)}
		} else {
			if cdxBom.Metadata.Component.Type == cdx.ComponentTypeContainer {
				splitImage := strings.Split(cdxBom.Metadata.Component.Name, "/")
				if len(splitImage) == 3 {
					// example: gcr.io/distroless/static:nonroot
					splitTag := strings.Split(splitImage[2], ":")
					if len(splitTag) == 2 {
						rootPackage.Purl = "pkg:oci/" + splitTag[0] + "@" + cdxBom.Metadata.Component.Version +
							"?repository_url=" + splitImage[0] + "/" + splitImage[1] + "/" + splitTag[0] + "&tag=" + splitTag[1]
					} else {
						// no tag specified
						rootPackage.Purl = "pkg:oci/" + splitImage[2] + "@" + cdxBom.Metadata.Component.Version +
							"?repository_url=" + splitImage[0] + "/" + splitImage[1] + "/" + splitImage[2] + "&tag="
					}
				} else if len(splitImage) == 2 {
					// example: library/debian:latest
					splitTag := strings.Split(splitImage[1], ":")
					if len(splitTag) == 2 {
						rootPackage.Purl = "pkg:oci/" + splitTag[0] + "@" + cdxBom.Metadata.Component.Version +
							"?repository_url=" + splitImage[0] + "/" + splitTag[0] + "&tag=" + splitTag[1]
					} else {
						// no tag specified
						rootPackage.Purl = "pkg:oci/" + splitImage[1] + "@" + cdxBom.Metadata.Component.Version +
							"?repository_url=" + splitImage[0] + "/" + splitImage[1] + "&tag="
					}
				}
			} else if cdxBom.Metadata.Component.Type == cdx.ComponentTypeFile {
				// example: file type ("/home/work/test/build/webserver/")
				rootPackage.Purl = "pkg:guac/file/" + cdxBom.Metadata.Component.Name + "&checksum=" + cdxBom.Metadata.Component.Version
			}
			rootPackage.Version = cdxBom.Metadata.Component.Version
			rootPackage.Digest = append(rootPackage.Digest, cdxBom.Metadata.Component.Version)
			rootPackage.Tags = []string{string(cdxBom.Metadata.Component.Type)}
		}
		c.rootComponent = component{
			curPackage:  rootPackage,
			depPackages: []*component{},
		}
	}
}

func (c *cyclonedxParser) addPackages(cdxBom *cdx.BOM) {
	if cdxBom.Components != nil {
		for _, comp := range *cdxBom.Components {
			// skipping over the "operating-system" type as it does not contain
			// the required purl for package node. Currently there is no use-case
			// to capture OS for GUAC.
			if comp.Type != cdx.ComponentTypeOS {
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
		}
	}

	if cdxBom.Dependencies == nil {
		return
	}
	for _, deps := range *cdxBom.Dependencies {
		currPkg, found := c.pkgMap[deps.Ref]
		if !found {
			continue
		}
		if deps.Dependencies != nil {
			for _, depPkg := range *deps.Dependencies {
				if depPkg, exist := c.pkgMap[depPkg]; exist {
					currPkg.depPackages = append(currPkg.depPackages, depPkg)
				}
			}
		}
	}
}

func parseCycloneDXBOM(doc *processor.Document) (*cdx.BOM, error) {
	bom := cdx.BOM{}
	switch doc.Format {
	case processor.FormatJSON:
		if err := json.Unmarshal(doc.Blob, &bom); err != nil {
			return nil, err
		}
	case processor.FormatXML:
		if err := xml.Unmarshal(doc.Blob, &bom); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognized CycloneDX format %s", doc.Format)
	}
	return &bom, nil
}

func (c *cyclonedxParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (c *cyclonedxParser) GetPredicates(ctx context.Context) *assembler.PlaceholderStruct {
	return nil
}
