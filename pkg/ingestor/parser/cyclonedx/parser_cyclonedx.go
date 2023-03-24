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
	"reflect"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

type cyclonedxParser struct {
	doc             *processor.Document
	packagePackages map[string][]model.PkgInputSpec

	cdxBom *cdx.BOM
}

func NewCycloneDXParser() common.DocumentParser {
	return &cyclonedxParser{
		packagePackages: map[string][]model.PkgInputSpec{},
	}
}

// Parse breaks out the document into the graph components
func (c *cyclonedxParser) Parse(ctx context.Context, doc *processor.Document) error {
	c.doc = doc
	cdxBom, err := parseCycloneDXBOM(doc)
	if err != nil {
		return fmt.Errorf("failed to parse cyclonedx BOM: %w", err)
	}
	c.cdxBom = cdxBom
	c.getTopLevelPackage(cdxBom)
	c.getPackages(cdxBom)

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *cyclonedxParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *cyclonedxParser) getTopLevelPackage(cdxBom *cdx.BOM) error {
	if cdxBom.Metadata.Component != nil {
		purl := cdxBom.Metadata.Component.PackageURL
		if cdxBom.Metadata.Component.PackageURL == "" {
			if cdxBom.Metadata.Component.Type == cdx.ComponentTypeContainer {
				//TODO(dejanb): Change prefix to pkg:guac/cdx and align it with spdx implementation
				splitImage := strings.Split(cdxBom.Metadata.Component.Name, "/")

				const (
					ociPrefix        = "pkg:oci/"
					repositoryURLKey = "?repository_url="
					tagKey           = "&tag="
				)

				splitTag := strings.Split(splitImage[len(splitImage)-1], ":")
				var repositoryURL string
				var tag string

				switch len(splitImage) {
				case 3:
					repositoryURL = splitImage[0] + "/" + splitImage[1] + "/" + splitTag[0]
				case 2:
					repositoryURL = splitImage[0] + "/" + splitTag[0]
				default:
					repositoryURL = ""
				}

				if len(splitTag) == 2 {
					tag = splitTag[1]
				}

				purl = fmt.Sprintf("%s%s@%s%s%s%s%s", ociPrefix, splitTag[0],
					cdxBom.Metadata.Component.Version, repositoryURLKey, repositoryURL, tagKey, tag)
			} else if cdxBom.Metadata.Component.Type == cdx.ComponentTypeFile {
				// example: file type ("/home/work/test/build/webserver/")
				purl = "pkg:guac/file/" + cdxBom.Metadata.Component.Name + "&checksum=" + cdxBom.Metadata.Component.Version
			}
		}
		topPackage, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		c.packagePackages[string(cdxBom.Metadata.Component.BOMRef)] = append(c.packagePackages[string(cdxBom.Metadata.Component.BOMRef)], *topPackage)
	}
	return nil
}

func (c *cyclonedxParser) getPackages(cdxBom *cdx.BOM) error {
	if cdxBom.Components != nil {
		for _, comp := range *cdxBom.Components {
			// skipping over the "operating-system" type as it does not contain
			// the required purl for package node. Currently there is no use-case
			// to capture OS for GUAC.
			if comp.Type != cdx.ComponentTypeOS {
				pkg, err := asmhelpers.PurlToPkg(comp.PackageURL)
				if err != nil {
					return err
				}
				c.packagePackages[string(comp.BOMRef)] = append(c.packagePackages[string(comp.BOMRef)], *pkg)
				//TODO(dejanb): Parse hashes and create artifact nodes and isOccurence relations https://github.com/guacsec/guac/issues/632
			}
		}
	}
	return nil
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

func (c *cyclonedxParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)

	preds := &assembler.IngestPredicates{}

	toplevel := c.getPackageElement(string(c.cdxBom.Metadata.Component.BOMRef))
	// adding top level package edge manually for all depends on package
	if toplevel != nil {
		preds.IsDependency = append(preds.IsDependency, common.CreateTopLevelIsDeps(toplevel[0], c.packagePackages, nil, "top-level package GUAC heuristic connecting to each file/package")...)
	}

	if c.cdxBom.Dependencies == nil {
		return preds
	}

	for _, deps := range *c.cdxBom.Dependencies {
		currPkg, found := c.packagePackages[deps.Ref]
		if !found {
			continue
		}
		if reflect.DeepEqual(currPkg, toplevel) {
			continue
		}
		if deps.Dependencies != nil {
			for _, depPkg := range *deps.Dependencies {
				if depPkg, exist := c.packagePackages[depPkg]; exist {
					for _, packNode := range currPkg {
						p, err := common.GetIsDep(packNode, depPkg, []model.PkgInputSpec{}, "CDX BOM Dependency")
						if err != nil {
							logger.Errorf("error generating CycloneDX edge %v", err)
							continue
						}
						if p != nil {
							preds.IsDependency = append(preds.IsDependency, *p)
						}
					}
				}
			}
		}
	}

	return preds
}

func (s *cyclonedxParser) getPackageElement(elementID string) []model.PkgInputSpec {
	if packNode, ok := s.packagePackages[string(elementID)]; ok {
		return packNode
	}
	return nil
}
