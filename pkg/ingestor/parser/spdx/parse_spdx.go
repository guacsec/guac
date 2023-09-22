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
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spdx/tools-golang/json"
	spdx "github.com/spdx/tools-golang/spdx"
	spdx_common "github.com/spdx/tools-golang/spdx/v2/common"
	"golang.org/x/exp/slices"
)

type spdxParser struct {
	// TODO: Add hasSBOMInputSpec when its created
	doc                 *processor.Document
	packagePackages     map[string][]*model.PkgInputSpec
	packageArtifacts    map[string][]*model.ArtifactInputSpec
	packageLegals       map[string][]*model.CertifyLegalInputSpec
	filePackages        map[string][]*model.PkgInputSpec
	fileArtifacts       map[string][]*model.ArtifactInputSpec
	topLevelPackages    map[string][]*model.PkgInputSpec
	identifierStrings   *common.IdentifierStrings
	spdxDoc             *spdx.Document
	topLevelIsHeuristic bool
	timeScanned         time.Time
}

func NewSpdxParser() common.DocumentParser {
	return &spdxParser{
		packagePackages:     map[string][]*model.PkgInputSpec{},
		packageArtifacts:    map[string][]*model.ArtifactInputSpec{},
		packageLegals:       map[string][]*model.CertifyLegalInputSpec{},
		filePackages:        map[string][]*model.PkgInputSpec{},
		fileArtifacts:       map[string][]*model.ArtifactInputSpec{},
		topLevelPackages:    map[string][]*model.PkgInputSpec{},
		identifierStrings:   &common.IdentifierStrings{},
		topLevelIsHeuristic: false,
	}
}

func (s *spdxParser) Parse(ctx context.Context, doc *processor.Document) error {
	s.doc = doc
	spdxDoc, err := parseSpdxBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse SPDX document: %w", err)
	}
	s.spdxDoc = spdxDoc
	if spdxDoc.CreationInfo == nil {
		return fmt.Errorf("SPDC documentd missing required \"creationInfo\" section.")
	}
	time, err := time.Parse(time.RFC3339, spdxDoc.CreationInfo.Created)
	if err != nil {
		return fmt.Errorf("SPDX document had invalid created time %q : %w", spdxDoc.CreationInfo.Created, err)
	}
	s.timeScanned = time
	if err := s.getPackages(); err != nil {
		return err
	}
	if err := s.getFiles(); err != nil {
		return err
	}
	return nil
}

// creating top level package manually until https://github.com/anchore/syft/issues/1241 is resolved
func (s *spdxParser) getTopLevelPackageSpdxIds() ([]string, error) {
	// TODO: Add CertifyPkg to make a connection from GUAC purl to OCI purl guessed
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	var spdxIds []string
	for _, r := range s.spdxDoc.Relationships {
		// If both sides of the relationship contain the same string,
		// it is not a valid DESCRIBES/DESCRIBED_BY relationship.
		if r.RefA.ElementRefID == r.RefB.ElementRefID {
			continue
		}

		if r.RefA.ElementRefID == "DOCUMENT" && r.Relationship == spdx_common.TypeRelationshipDescribe {
			spdxIds = append(spdxIds, string(r.RefB.ElementRefID))
		} else if r.Relationship == spdx_common.TypeRelationshipDescribeBy && r.RefB.ElementRefID == "DOCUMENT" {
			spdxIds = append(spdxIds, string(r.RefA.ElementRefID))
		}
	}

	return spdxIds, nil
}

func (s *spdxParser) getPackages() error {
	topLevelSpdxIds, err := s.getTopLevelPackageSpdxIds()
	if err != nil {
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

		if slices.Contains(topLevelSpdxIds, string(pac.PackageSPDXIdentifier)) {
			s.topLevelPackages[string(s.spdxDoc.SPDXIdentifier)] = append(s.topLevelPackages[string(s.spdxDoc.SPDXIdentifier)], pkg)
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

		if pac.PackageLicenseDeclared != "" ||
			pac.PackageLicenseConcluded != "" ||
			pac.PackageCopyrightText != "" {
			cl := &model.CertifyLegalInputSpec{
				DeclaredLicense:   pac.PackageLicenseDeclared,
				DiscoveredLicense: pac.PackageLicenseConcluded,
				Attribution:       pac.PackageCopyrightText,
				Justification:     "Found in SPDX document.",
				TimeScanned:       s.timeScanned,
			}
			if pac.PackageLicenseComments != "" {
				cl.Justification = fmt.Sprintf("%s : %s", cl.Justification, pac.PackageLicenseComments)
			}
			s.packageLegals[string(pac.PackageSPDXIdentifier)] = append(
				s.packageLegals[string(pac.PackageSPDXIdentifier)], cl)
		}

	}

	// If there is no top level Spdx Id that can be derived from the relationships, we take a best guess for the SpdxId.
	if _, ok := s.topLevelPackages[string(s.spdxDoc.SPDXIdentifier)]; !ok {
		purl := "pkg:guac/spdx/" + asmhelpers.SanitizeString(s.spdxDoc.DocumentName)
		topPackage, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		s.topLevelPackages[string(s.spdxDoc.SPDXIdentifier)] = append(s.topLevelPackages[string(s.spdxDoc.SPDXIdentifier)], topPackage)
		s.identifierStrings.PurlStrings = append(s.identifierStrings.PurlStrings, purl)
		s.topLevelIsHeuristic = true
	}

	return nil
}

func (s *spdxParser) getFiles() error {
	for _, file := range s.spdxDoc.Files {

		// if checksums exists create an artifact for each of them
		for _, checksum := range file.Checksums {
			if isEmptyChecksum(checksum.Value) {
				continue
			}
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

func parseSpdxBlob(p []byte) (*spdx.Document, error) {
	return json.Read(bytes.NewReader(p))
}

func (s *spdxParser) getPackageElement(elementID string) []*model.PkgInputSpec {
	if packNode, ok := s.packagePackages[string(elementID)]; ok {
		return packNode
	}
	return nil
}

func (s *spdxParser) getTopLevelPackageElement(elementID string) []*model.PkgInputSpec {
	if packNode, ok := s.topLevelPackages[string(elementID)]; ok {
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

	topLevel := s.getTopLevelPackageElement(string(s.spdxDoc.SPDXIdentifier))
	if topLevel == nil {
		logger.Errorf("error getting predicates: unable to find top level package element")
		return preds
	} else {
		// adding top level package edge manually for all depends on package
		for _, topLevelPkg := range topLevel {
			preds.HasSBOM = append(preds.HasSBOM, common.CreateTopLevelHasSBOM(topLevelPkg, s.doc))
		}

		if s.topLevelIsHeuristic {
			preds.IsDependency = append(preds.IsDependency,
				common.CreateTopLevelIsDeps(topLevel[0], s.packagePackages, s.filePackages,
					"top-level package GUAC heuristic connecting to each file/package")...)
		}
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

	for id, cls := range s.packageLegals {
		for _, cl := range cls {
			dec := common.ParseLicenses(cl.DeclaredLicense, s.spdxDoc.CreationInfo.LicenseListVersion)
			dis := common.ParseLicenses(cl.DiscoveredLicense, s.spdxDoc.CreationInfo.LicenseListVersion)
			for i := range dec {
				o, n := fixLicense(ctx, &dec[i], s.spdxDoc.OtherLicenses)
				if o != "" {
					exp := strings.ReplaceAll(cl.DeclaredLicense, o, n)
					cl.DeclaredLicense = exp
				}
			}
			for i := range dis {
				o, n := fixLicense(ctx, &dis[i], s.spdxDoc.OtherLicenses)
				if o != "" {
					exp := strings.ReplaceAll(cl.DiscoveredLicense, o, n)
					cl.DiscoveredLicense = exp
				}
			}
			for _, pkg := range s.packagePackages[id] {
				cli := assembler.CertifyLegalIngest{
					Pkg:          pkg,
					Declared:     dec,
					Discovered:   dis,
					CertifyLegal: cl,
				}
				preds.CertifyLegal = append(preds.CertifyLegal, cli)
			}
		}
	}

	return preds
}

func fixLicense(ctx context.Context, l *generated.LicenseInputSpec, ol []*spdx.OtherLicense) (string, string) {
	logger := logging.FromContext(ctx)
	if !strings.HasPrefix(l.Name, "LicenseRef-") {
		return "", ""
	}
	oldName := l.Name
	l.ListVersion = nil
	found := false
	for _, o := range ol {
		if o.LicenseIdentifier == l.Name {
			l.Inline = &o.ExtractedText
			found = true
			break
		}
	}
	if !found {
		logger.Error("License identifier %q not found in OtherLicenses", l.Name)
		s := "Not found"
		l.Inline = &s
	}
	l.Name = common.HashLicense(*l.Inline)
	return oldName, l.Name
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

func getJustification(r *spdx.Relationship) string {
	s := fmt.Sprintf("Derived from SPDX %s relationship", r.Relationship)
	if len(r.RelationshipComment) > 0 {
		s += fmt.Sprintf("with comment: %s", r.RelationshipComment)
	}
	return s
}

func isEmptyChecksum(v string) bool {
	return map[string]bool{
		// all 0 hash
		"0000000000000000000000000000000000000000":                         true,
		"0000000000000000000000000000000000000000000000000000000000000000": true,
		// sha1 empty file
		"da39a3ee5e6b4b0d3255bfef95601890afd80709": true,
		// sha256 empty file
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
		// sha512 empty file
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": true,
		// TODO: add the same for other SPDX hash algorithms available
		// ref: https://github.com/guacsec/guac/issues/1229
	}[v]
}
