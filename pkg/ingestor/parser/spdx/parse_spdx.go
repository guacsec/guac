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
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	spdx_common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
)

type spdxParser struct {
	// TODO: Add hasSBOMInputSpec when its created
	doc               *processor.Document
	packagePackages   map[string][]*model.PkgInputSpec
	packageArtifacts  map[string][]*model.ArtifactInputSpec
	filePackages      map[string][]*model.PkgInputSpec
	fileArtifacts     map[string][]*model.ArtifactInputSpec
	identifierStrings *common.IdentifierStrings
	spdxDoc           *v2_2.Document
}

func NewSpdxParser() common.DocumentParser {
	return &spdxParser{
		packagePackages:   map[string][]*model.PkgInputSpec{},
		packageArtifacts:  map[string][]*model.ArtifactInputSpec{},
		filePackages:      map[string][]*model.PkgInputSpec{},
		fileArtifacts:     map[string][]*model.ArtifactInputSpec{},
		identifierStrings: &common.IdentifierStrings{},
	}
}

func (s *spdxParser) Parse(ctx context.Context, doc *processor.Document) error {
	s.doc = doc
	spdxDoc, err := parseSpdxBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse SPDX document: %w", err)
	}
	s.spdxDoc = spdxDoc
	if err := s.getPackages(); err != nil {
		return err
	}
	if err := s.getFiles(); err != nil {
		return err
	}
	return nil
}

// creating top level package manually until https://github.com/anchore/syft/issues/1241 is resolved
func (s *spdxParser) getTopLevelPackage() error {
	// TODO: Add CertifyPkg to make a connection from GUAC purl to OCI purl guessed
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye

	// TODO (dejanb): do a quick check for SPDX to see if there are any "DESCRIBES" relationships
	// from the document and omit this top level heuristic package otherwise.

	// Currently create TopLevel package as well in some cases where we guess that the SPDX document
	// may not encode it
	var purl string = "pkg:guac/spdx/" + asmhelpers.SanitizeString(s.spdxDoc.DocumentName)

	if purl != "" {
		topPackage, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		s.packagePackages[string(s.spdxDoc.SPDXIdentifier)] = append(s.packagePackages[string(s.spdxDoc.SPDXIdentifier)], topPackage)
		s.identifierStrings.PurlStrings = append(s.identifierStrings.PurlStrings, purl)
	}
	return nil
}

func (s *spdxParser) getPackages() error {
	if err := s.getTopLevelPackage(); err != nil {
		return err
	}
	for _, pac := range s.spdxDoc.Packages {
		// for each package create a package for each of them
		purl := ""
		for _, ext := range pac.PackageExternalReferences {
			if ext.RefType == spdx_common.TypePackageManagerPURL {
				purl = ext.Locator
			}

		}
		if purl == "" {
			purl = asmhelpers.GuacPkgPurl(pac.PackageName, &pac.PackageVersion)
		}

		s.identifierStrings.PurlStrings = append(s.identifierStrings.PurlStrings, purl)

		pkg, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		s.packagePackages[string(pac.PackageSPDXIdentifier)] = append(s.packagePackages[string(pac.PackageSPDXIdentifier)], pkg)

		// if checksums exists create an artifact for each of them
		for _, checksum := range pac.PackageChecksums {
			artifact := &model.ArtifactInputSpec{
				Algorithm: strings.ToLower(string(checksum.Algorithm)),
				Digest:    checksum.Value,
			}
			s.packageArtifacts[string(pac.PackageSPDXIdentifier)] = append(s.packageArtifacts[string(pac.PackageSPDXIdentifier)], artifact)
		}

	}
	return nil
}

func (s *spdxParser) getFiles() error {
	for _, file := range s.spdxDoc.Files {

		// if checksums exists create an artifact for each of them
		for _, checksum := range file.Checksums {
			// for each file create a package for each of them so they can be referenced as a dependency
			purl := asmhelpers.GuacFilePurl(strings.ToLower(string(checksum.Algorithm)), checksum.Value, &file.FileName)
			pkg, err := asmhelpers.PurlToPkg(purl)
			if err != nil {
				return err
			}
			s.filePackages[string(file.FileSPDXIdentifier)] = append(s.filePackages[string(file.FileSPDXIdentifier)], pkg)

			artifact := &model.ArtifactInputSpec{
				Algorithm: strings.ToLower(string(checksum.Algorithm)),
				Digest:    checksum.Value,
			}
			s.fileArtifacts[string(file.FileSPDXIdentifier)] = append(s.fileArtifacts[string(file.FileSPDXIdentifier)], artifact)
		}
	}
	return nil
}

func parseSpdxBlob(p []byte) (*v2_2.Document, error) {
	doc := &v2_2.Document{}
	if err := doc.UnmarshalJSON(p); err != nil {
		return nil, err
	}
	return doc, nil
}

func (s *spdxParser) getPackageElement(elementID string) []*model.PkgInputSpec {
	if packNode, ok := s.packagePackages[string(elementID)]; ok {
		return packNode
	}
	return nil
}

func (s *spdxParser) getFileElement(elementID string) []*model.PkgInputSpec {
	if fileNode, ok := s.filePackages[string(elementID)]; ok {
		return fileNode
	}
	return nil
}

func (s *spdxParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)

	preds := &assembler.IngestPredicates{}

	toplevel := s.getPackageElement("DOCUMENT")
	// adding top level package edge manually for all depends on package
	if toplevel != nil {
		preds.IsDependency = append(preds.IsDependency, common.CreateTopLevelIsDeps(toplevel[0], s.packagePackages, s.filePackages, "top-level package GUAC heuristic connecting to each file/package")...)
		preds.HasSBOM = append(preds.HasSBOM, common.CreateTopLevelHasSBOM(toplevel[0], s.doc))
	}
	for _, rel := range s.spdxDoc.Relationships {
		var foundId string
		var relatedId string

		if isDependency(rel.Relationship) {
			foundId = string(rel.RefA.ElementRefID)
			relatedId = string(rel.RefB.ElementRefID)
		} else if isDependent(rel.Relationship) {
			foundId = string(rel.RefB.ElementRefID)
			relatedId = string(rel.RefA.ElementRefID)
		} else {
			continue
		}

		foundPackNodes := s.getPackageElement(foundId)
		foundFileNodes := s.getFileElement(foundId)
		relatedPackNodes := s.getPackageElement(relatedId)
		relatedFileNodes := s.getFileElement(relatedId)

		justification := getJustification(rel)

		for _, packNode := range foundPackNodes {
			p, err := common.GetIsDep(packNode, relatedPackNodes, relatedFileNodes, justification)
			if err != nil {
				logger.Errorf("error generating spdx edge %v", err)
				continue
			}
			if p != nil {
				preds.IsDependency = append(preds.IsDependency, *p)
			}
		}
		for _, fileNode := range foundFileNodes {
			p, err := common.GetIsDep(fileNode, relatedPackNodes, relatedFileNodes, justification)
			if err != nil {
				logger.Errorf("error generating spdx edge %v", err)
				continue
			}
			if p != nil {
				preds.IsDependency = append(preds.IsDependency, *p)
			}
		}
	}

	// Create predicates for IsOccurrence for all artifacts found
	for id := range s.fileArtifacts {
		for _, pkg := range s.filePackages[id] {
			for _, art := range s.fileArtifacts[id] {
				preds.IsOccurrence = append(preds.IsOccurrence, assembler.IsOccurrenceIngest{
					Pkg:      pkg,
					Artifact: art,
					IsOccurrence: &model.IsOccurrenceInputSpec{
						Justification: "spdx file with checksum",
					},
				})
			}
		}
	}

	for id := range s.packagePackages {
		for _, pkg := range s.packagePackages[id] {
			for _, art := range s.packageArtifacts[id] {
				preds.IsOccurrence = append(preds.IsOccurrence, assembler.IsOccurrenceIngest{
					Pkg:      pkg,
					Artifact: art,
					IsOccurrence: &model.IsOccurrenceInputSpec{
						Justification: "spdx package with checksum",
					},
				})
			}
		}
	}

	return preds
}

func isDependency(rel string) bool {
	return map[string]bool{
		spdx_common.TypeRelationshipContains:  true,
		spdx_common.TypeRelationshipDependsOn: true,
	}[rel]
}

func isDependent(rel string) bool {
	return map[string]bool{
		spdx_common.TypeRelationshipContainedBy:  true,
		spdx_common.TypeRelationshipDependencyOf: true,
	}[rel]
}

func (s *spdxParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (s *spdxParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return s.identifierStrings, nil
}

func getJustification(r *v2_2.Relationship) string {
	s := fmt.Sprintf("Derived from SPDX %s relationship", r.Relationship)
	if len(r.RelationshipComment) > 0 {
		s += fmt.Sprintf("with comment: %s", r.RelationshipComment)
	}
	return s
}
