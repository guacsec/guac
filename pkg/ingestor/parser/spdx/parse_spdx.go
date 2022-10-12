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
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_common "github.com/spdx/tools-golang/spdx/common"
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

func (s *spdxParser) Parse(ctx context.Context, doc *processor.Document) error {
	spdxDoc, err := parseSpdxBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse SPDX document: %w", err)
	}
	s.spdxDoc = spdxDoc
	s.getPackages()
	s.getFiles()
	return nil
}

// creating top level package manually until https://github.com/anchore/syft/issues/1241 is resolved
func (s *spdxParser) getTopLevelPackage() {
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	splitImage := strings.Split(s.spdxDoc.DocumentName, "/")
	if len(splitImage) == 3 {
		topPackage := assembler.PackageNode{}
		topPackage.Purl = "pkg:oci/" + splitImage[2] + "?repository_url=" + splitImage[0] + "/" + splitImage[1]
		topPackage.Name = s.spdxDoc.DocumentName
		s.packages[string(s.spdxDoc.SPDXIdentifier)] = append(s.packages[string(s.spdxDoc.SPDXIdentifier)], topPackage)
	} else if len(splitImage) == 2 {
		topPackage := assembler.PackageNode{}
		topPackage.Purl = "pkg:oci/" + splitImage[1] + "?repository_url=" + splitImage[0]
		topPackage.Name = s.spdxDoc.DocumentName
		s.packages[string(s.spdxDoc.SPDXIdentifier)] = append(s.packages[string(s.spdxDoc.SPDXIdentifier)], topPackage)
	}
}

func (s *spdxParser) getPackages() {
	s.getTopLevelPackage()
	for _, pac := range s.spdxDoc.Packages {
		currentPackage := assembler.PackageNode{}
		currentPackage.Name = pac.PackageName
		for _, ext := range pac.PackageExternalReferences {
			if strings.HasPrefix(ext.RefType, "cpe") {
				currentPackage.CPEs = append(currentPackage.CPEs, ext.Locator)
			} else if ext.RefType == spdx_common.TypePackageManagerPURL {
				currentPackage.Purl = ext.Locator
			}
		}
		for _, checksum := range pac.PackageChecksums {
			currentPackage.Digest = append(currentPackage.Digest, strings.ToLower(string(checksum.Algorithm))+":"+checksum.Value)
		}
		s.packages[string(pac.PackageSPDXIdentifier)] = append(s.packages[string(pac.PackageSPDXIdentifier)], currentPackage)
	}
}

func (s *spdxParser) getFiles() {
	for _, file := range s.spdxDoc.Files {
		currentFile := assembler.ArtifactNode{}
		for _, checksum := range file.Checksums {
			currentFile.Name = file.FileName
			currentFile.Digest = strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
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

func (s *spdxParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
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

func (s *spdxParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	logger := logging.FromContext(ctx)
	edges := []assembler.GuacEdge{}
	toplevel := s.getPackageElement("SPDXRef-DOCUMENT")
	// adding top level package edge manually for all depends on package
	if toplevel != nil {
		edges = append(edges, createTopLevelEdges(toplevel[0], s.packages, s.files)...)
	}
	for _, rel := range s.spdxDoc.Relationships {
		foundPackNodes := s.getPackageElement("SPDXRef-" + string(rel.RefA.ElementRefID))
		foundFileNodes := s.getFileElement("SPDXRef-" + string(rel.RefA.ElementRefID))
		relatedPackNodes := s.getPackageElement("SPDXRef-" + string(rel.RefB.ElementRefID))
		relatedFileNodes := s.getFileElement("SPDXRef-" + string(rel.RefB.ElementRefID))
		for _, packNode := range foundPackNodes {
			createdEdge, err := getEdge(packNode, rel.Relationship, relatedPackNodes, relatedFileNodes)
			if err != nil {
				logger.Errorf("error generating spdx edge %v", err)
				continue
			}
			if createdEdge != nil {
				edges = append(edges, createdEdge)
			}
		}
		for _, fileNode := range foundFileNodes {
			createdEdge, err := getEdge(fileNode, rel.Relationship, relatedPackNodes, relatedFileNodes)
			if err != nil {
				logger.Errorf("error generating spdx edge %v", err)
				continue
			}
			if createdEdge != nil {
				edges = append(edges, createdEdge)
			}
		}
	}
	return edges
}

func createTopLevelEdges(toplevel assembler.PackageNode, packages map[string][]assembler.PackageNode, files map[string][]assembler.ArtifactNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, packNodes := range packages {
		for _, packNode := range packNodes {
			if packNode.Purl != toplevel.Purl {
				e := assembler.DependsOnEdge{
					PackageNode:       toplevel,
					PackageDependency: packNode,
				}
				edges = append(edges, e)
			}
		}
	}

	for _, fileNodes := range files {
		for _, fileNode := range fileNodes {
			e := assembler.DependsOnEdge{
				PackageNode:        toplevel,
				ArtifactDependency: fileNode,
			}
			edges = append(edges, e)
		}
	}

	return edges
}

func getEdge(foundNode assembler.GuacNode, relationship string, relatedPackNodes []assembler.PackageNode, relatedFileNodes []assembler.ArtifactNode) (assembler.GuacEdge, error) {
	if len(relatedFileNodes) > 0 {
		for _, rfileNode := range relatedFileNodes {
			return getEdgeByType(relationship, foundNode, rfileNode)
		}
	} else if len(relatedPackNodes) > 0 {
		for _, rpackNode := range relatedPackNodes {
			return getEdgeByType(relationship, foundNode, rpackNode)
		}
	}
	return nil, nil
}

func getEdgeByType(relationship string, foundNode assembler.GuacNode, relatedNode assembler.GuacNode) (assembler.GuacEdge, error) {
	switch relationship {
	case spdx_common.TypeRelationshipContains:
		return getContainsEdge(foundNode, relatedNode)
	case spdx_common.TypeRelationshipDependsOn:
		return getDependsOnEdge(foundNode, relatedNode), nil
	}
	return nil, nil
}

func getContainsEdge(foundNode assembler.GuacNode, relatedNode assembler.GuacNode) (assembler.GuacEdge, error) {
	e := assembler.ContainsEdge{}
	if foundNode.Type() == "Package" {
		e.PackageNode = foundNode.(assembler.PackageNode)
	} else {
		return nil, errors.New("node type mismatch during contains edge creation")
	}
	if relatedNode.Type() == "Artifact" {
		e.ContainedArtifact = relatedNode.(assembler.ArtifactNode)
	} else {
		return nil, errors.New("node type mismatch during contains edge creation")
	}
	return e, nil
}

func getDependsOnEdge(foundNode assembler.GuacNode, relatedNode assembler.GuacNode) assembler.GuacEdge {
	e := assembler.DependsOnEdge{}
	if foundNode.Type() == "Package" {
		e.PackageNode = foundNode.(assembler.PackageNode)
	} else {
		e.ArtifactNode = foundNode.(assembler.ArtifactNode)
	}

	if relatedNode.Type() == "Package" {
		e.PackageDependency = relatedNode.(assembler.PackageNode)
	} else {
		e.ArtifactDependency = relatedNode.(assembler.ArtifactNode)
	}
	return e
}

func (s *spdxParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

func (s *spdxParser) GetDocType() processor.DocumentType {
	return processor.DocumentSPDX
}
