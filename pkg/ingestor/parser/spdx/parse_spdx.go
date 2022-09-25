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

package spdx

import (
	"bytes"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2_2"
)

type spdxParser struct {
	packages map[string][]assembler.PackageNode
	files    map[string][]assembler.ArtifactNode
	spdxDoc  *v2_2.Document
}

func NewSpdxParser() *spdxParser {
	return &spdxParser{
		packages: map[string][]assembler.PackageNode{},
		files:    map[string][]assembler.ArtifactNode{},
	}
}

func (s *spdxParser) Parse(doc *processor.Document) error {
	spdxDoc, err := parseSpdxBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse SPDX document: %w", err)
	}
	s.spdxDoc = spdxDoc
	s.getPackages()
	s.getFiles()
	return nil
}

func (s *spdxParser) getPackages() {
	for _, pac := range s.spdxDoc.Packages {
		currentPackage := assembler.PackageNode{}
		currentPackage.Name = pac.PackageName
		if len(pac.PackageExternalReferences) > 0 {
			for _, ext := range pac.PackageExternalReferences {
				if ext.Category == "SECURITY" {
					currentPackage.CPEs = append(currentPackage.CPEs, ext.Locator)
				}
				if ext.Category == "PACKAGE-MANAGER" {
					currentPackage.Purl = ext.Locator
				}
			}
		}
		if len(pac.PackageChecksums) > 0 {
			for _, checksum := range pac.PackageChecksums {
				currentPackage.Digest = string(checksum.Algorithm) + ":" + checksum.Value
				s.packages[string(pac.PackageSPDXIdentifier)] = append(s.packages[string(pac.PackageSPDXIdentifier)], currentPackage)
			}
		} else {
			s.packages[string(pac.PackageSPDXIdentifier)] = append(s.packages[string(pac.PackageSPDXIdentifier)], currentPackage)
		}

	}
}

func (s *spdxParser) getFiles() {
	for _, file := range s.spdxDoc.Files {
		currentFile := assembler.ArtifactNode{}
		//todo: What to do when files dont have hashes?
		for _, checksum := range file.Checksums {
			currentFile.Name = file.FileName
			currentFile.Digest = string(checksum.Algorithm) + ":" + checksum.Value
			s.files[string(file.FileSPDXIdentifier)] = append(s.files[string(file.FileSPDXIdentifier)], currentFile)
		}
	}
}

func parseSpdxBlob(p []byte) (*v2_2.Document, error) {
	reader := bytes.NewReader(p)
	spdx, err := spdx_json.Load2_2(reader)
	if err != nil {
		return nil, err
	}
	return spdx, nil
}

func (s *spdxParser) CreateNodes() []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, packNodes := range s.packages {
		for _, packNode := range packNodes {
			nodes = append(nodes, packNode)
		}
	}
	for _, fileNodes := range s.files {
		for _, fileNode := range fileNodes {
			nodes = append(nodes, fileNode)
		}
	}
	return nodes
}

func (s *spdxParser) getPackageElement(elementID string) []assembler.PackageNode {
	if packNode, ok := s.packages[string(elementID)]; ok {
		return packNode
	}
	return nil
}

func (s *spdxParser) getFileElement(elementID string) []assembler.ArtifactNode {
	if fileNode, ok := s.files[string(elementID)]; ok {
		return fileNode
	}
	return nil
}

func (s *spdxParser) CreateEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, rel := range s.spdxDoc.Relationships {
		foundPackNodes := s.getPackageElement(string(rel.RefA.ElementRefID))
		foundFileNodes := s.getFileElement(string(rel.RefA.ElementRefID))
		relatedPackNodes := s.getPackageElement(string(rel.RefB.ElementRefID))
		relatedFileNodes := s.getFileElement(string(rel.RefB.ElementRefID))
		if len(foundPackNodes) > 0 {
			for _, packNode := range foundPackNodes {
				if len(relatedFileNodes) > 0 {
					for _, fileNode := range relatedFileNodes {
						edges = append(edges, sortNodes(packNode, fileNode))
					}
				}
				if len(relatedPackNodes) > 0 {
					for _, packNode := range relatedPackNodes {
						edges = append(edges, sortNodes(packNode, packNode))
					}
				}
			}
		}
		if len(foundFileNodes) > 0 {
			for _, fileNode := range foundFileNodes {
				if len(relatedFileNodes) > 0 {
					for _, fileNode := range relatedFileNodes {
						edges = append(edges, sortNodes(fileNode, fileNode))
					}
				}
				if len(relatedPackNodes) > 0 {
					for _, packNode := range relatedPackNodes {
						edges = append(edges, sortNodes(fileNode, packNode))
					}
				}
			}
		}
	}
	return edges
}

func sortNodes(foundNode assembler.GuacNode, relatedNode assembler.GuacNode) assembler.GuacEdge {
	if foundNode.Type() == "Package" && relatedNode.Type() == "Package" {
		return assembler.DependsOnEdge{PackageNode: foundNode.(assembler.PackageNode), PackageDependency: relatedNode.(assembler.PackageNode)}
	}
	if foundNode.Type() == "Package" && relatedNode.Type() == "Artifact" {
		return assembler.DependsOnEdge{PackageNode: foundNode.(assembler.PackageNode), ArtifactDependency: relatedNode.(assembler.ArtifactNode)}
	}
	if foundNode.Type() == "Artifact" && relatedNode.Type() == "Artifact" {
		return assembler.DependsOnEdge{ArtifactNode: foundNode.(assembler.ArtifactNode), ArtifactDependency: relatedNode.(assembler.ArtifactNode)}
	}
	if foundNode.Type() == "Artifact" && relatedNode.Type() == "Package" {
		return assembler.DependsOnEdge{ArtifactNode: foundNode.(assembler.ArtifactNode), PackageDependency: relatedNode.(assembler.PackageNode)}
	}
	return nil
}

func (s *spdxParser) GetIdentities() []assembler.IdentityNode {
	return nil
}

func (s *spdxParser) GetDocType() processor.DocumentType {
	return processor.DocumentSPDX
}
