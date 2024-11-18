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
	"slices"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spdx/tools-golang/json"
	spdx "github.com/spdx/tools-golang/spdx"
	spdx_common "github.com/spdx/tools-golang/spdx/v2/common"
)

type spdxParser struct {
	// TODO: Add hasSBOMInputSpec when its created
	doc                 *processor.Document
	packagePackages     map[string][]*model.PkgInputSpec
	packageArtifacts    map[string][]*model.ArtifactInputSpec
	packageLegals       map[string][]*model.CertifyLegalInputSpec
	filePackages        map[string][]*model.PkgInputSpec
	fileArtifacts       map[string][]*model.ArtifactInputSpec
	licenseInLine       map[string]string
	topLevelPackages    []*model.PkgInputSpec
	topLevelArtifacts   map[string][]*model.ArtifactInputSpec
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
		topLevelArtifacts:   make(map[string][]*model.ArtifactInputSpec),
		licenseInLine:       map[string]string{},
		identifierStrings:   &common.IdentifierStrings{},
		topLevelIsHeuristic: false,
	}
}

// initializeSPDXParser clears out all values for the next iteration
func (s *spdxParser) initializeSPDXParser() {
	s.doc = nil
	s.packagePackages = map[string][]*model.PkgInputSpec{}
	s.packageArtifacts = map[string][]*model.ArtifactInputSpec{}
	s.packageLegals = map[string][]*model.CertifyLegalInputSpec{}
	s.filePackages = map[string][]*model.PkgInputSpec{}
	s.fileArtifacts = map[string][]*model.ArtifactInputSpec{}
	s.topLevelPackages = make([]*model.PkgInputSpec, 0)
	s.topLevelArtifacts = map[string][]*model.ArtifactInputSpec{}
	s.licenseInLine = map[string]string{}
	s.identifierStrings = &common.IdentifierStrings{}
	s.spdxDoc = nil
	s.topLevelIsHeuristic = false
	s.timeScanned = time.Now()
}

func (s *spdxParser) Parse(ctx context.Context, doc *processor.Document) error {
	s.initializeSPDXParser()
	s.doc = doc
	spdxDoc, err := parseSpdxBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse SPDX document: %w", err)
	}
	s.spdxDoc = spdxDoc
	if spdxDoc.CreationInfo == nil {
		return fmt.Errorf("SPDX document missing required \"creationInfo\" section")
	}
	time, err := time.Parse(time.RFC3339, spdxDoc.CreationInfo.Created)
	if err != nil {
		return fmt.Errorf("SPDX document had invalid created time %q : %w", spdxDoc.CreationInfo.Created, err)
	}
	s.timeScanned = time

	topLevelSPDXIDs, err := s.getTopLevelSPDXIDs()
	if err != nil {
		return err
	}

	if err := s.getFiles(topLevelSPDXIDs); err != nil {
		return err
	}

	if err := s.getPackages(topLevelSPDXIDs); err != nil {
		return err
	}

	// collect SPDX otherLicenses to InLineMap to be used for license predicate creation
	for _, o := range s.spdxDoc.OtherLicenses {
		s.licenseInLine[o.LicenseIdentifier] = o.ExtractedText
	}

	return nil
}

// creating top level IDs manually until https://github.com/anchore/syft/issues/1241 is resolved
func (s *spdxParser) getTopLevelSPDXIDs() ([]string, error) {
	// TODO: Add CertifyPkg to make a connection from GUAC purl to OCI purl guessed
	// oci purl: pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	var spdxIds []string
	for _, r := range s.spdxDoc.Relationships {
		if r == nil {
			// when the upstream parser in https://github.com/spdx/tools-golang does not
			// include null relationships in v2.2 SBOMs, we can remove this code
			continue
		}

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

func (s *spdxParser) getPackages(topLevelSPDXIDs []string) error {
	for _, pac := range s.spdxDoc.Packages {
		// for each package create a package for each of them
		purls := make([]string, 0)
		for _, ext := range pac.PackageExternalReferences {
			if ext.RefType == spdx_common.TypePackageManagerPURL {
				purls = append(purls, ext.Locator)
			}
		}
		if len(purls) == 0 {
			purls = append(purls, asmhelpers.GuacPkgPurl(pac.PackageName, &pac.PackageVersion))
		}

		s.identifierStrings.PurlStrings = append(s.identifierStrings.PurlStrings, purls...)

		for _, purl := range purls {
			pkg, err := asmhelpers.PurlToPkg(purl)
			if err != nil {
				return err
			}

			if slices.Contains(topLevelSPDXIDs, string(pac.PackageSPDXIdentifier)) {
				s.topLevelPackages = append(s.topLevelPackages, pkg)
			}
			s.packagePackages[string(pac.PackageSPDXIdentifier)] = append(s.packagePackages[string(pac.PackageSPDXIdentifier)], pkg)
		}

		// if checksums exists create an artifact for each of them
		for _, checksum := range pac.PackageChecksums {
			art := &model.ArtifactInputSpec{
				Algorithm: strings.ToLower(string(checksum.Algorithm)),
				Digest:    checksum.Value,
			}
			id := string(pac.PackageSPDXIdentifier)
			if slices.Contains(topLevelSPDXIDs, id) {
				s.topLevelArtifacts[id] = append(s.topLevelArtifacts[id], art)
			}
			s.packageArtifacts[id] = append(s.packageArtifacts[id], art)
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
	if len(s.topLevelPackages) == 0 {
		purl := "pkg:guac/spdx/" + asmhelpers.SanitizeString(s.spdxDoc.DocumentName)
		topPackage, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		s.topLevelPackages = append(s.topLevelPackages, topPackage)
		s.identifierStrings.PurlStrings = append(s.identifierStrings.PurlStrings, purl)
		s.topLevelIsHeuristic = true
	}

	return nil
}

func (s *spdxParser) getFiles(topLevelSPDXIDs []string) error {
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
			if slices.Contains(topLevelSPDXIDs, string(file.FileSPDXIdentifier)) {
				s.topLevelPackages = append(s.topLevelPackages, pkg)
			}
			s.filePackages[string(file.FileSPDXIdentifier)] = append(s.filePackages[string(file.FileSPDXIdentifier)], pkg)

			art := &model.ArtifactInputSpec{
				Algorithm: strings.ToLower(string(checksum.Algorithm)),
				Digest:    checksum.Value,
			}

			id := string(file.FileSPDXIdentifier)
			if slices.Contains(topLevelSPDXIDs, id) {
				s.topLevelArtifacts[id] = append(s.topLevelArtifacts[id], art)
			}
			s.fileArtifacts[id] = append(s.fileArtifacts[id], art)
		}
	}
	return nil
}

func parseSpdxBlob(p []byte) (*spdx.Document, error) {
	return json.Read(bytes.NewReader(p))
}

func (s *spdxParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)
	preds := &assembler.IngestPredicates{}

	if len(s.topLevelArtifacts) == 0 && len(s.topLevelPackages) == 0 {
		logger.Errorf("error getting predicates: unable to find top level artifact or package element")
		return preds
	} else {
		// adding top level package edge manually for all depends on package
		timestamp, err := time.Parse(time.RFC3339, s.spdxDoc.CreationInfo.Created)
		if err != nil {
			logger.Errorf("SPDX document had invalid created time %q : %w", s.spdxDoc.CreationInfo.Created, err)
			return nil
		}

		if len(s.topLevelArtifacts) > 0 {
			for _, arts := range s.topLevelArtifacts {
				for _, art := range arts {
					preds.HasSBOM = append(preds.HasSBOM, common.CreateTopLevelHasSBOMFromArtifact(art, s.doc, s.spdxDoc.DocumentNamespace, timestamp))
				}
			}

			if len(s.topLevelArtifacts) != len(s.topLevelPackages) {
				logger.Warnf("Top-level unique artifact count (%d) and top-level package count (%d) are mismatched. SBOM ingestion may not be as expected.",
					len(s.topLevelArtifacts), len(s.topLevelPackages))
			}
		} else {
			for _, topLevelPkg := range s.topLevelPackages {
				preds.HasSBOM = append(preds.HasSBOM, common.CreateTopLevelHasSBOMFromPkg(topLevelPkg, s.doc, s.spdxDoc.DocumentNamespace, timestamp))
			}
		}

		if s.topLevelIsHeuristic {
			preds.IsDependency = append(preds.IsDependency,
				common.CreateTopLevelIsDeps(s.topLevelPackages[0], s.packagePackages, s.filePackages,
					"top-level package GUAC heuristic connecting to each file/package")...)
		}
	}
	for _, rel := range s.spdxDoc.Relationships {
		if rel == nil {
			// when the upstream parser in https://github.com/spdx/tools-golang does not
			// include null relationships in v2.2 SBOMs, we can remove this code
			continue
		}

		var foundId string
		var relatedId string

		if isDependency(rel.Relationship) {
			foundId = string(rel.RefA.ElementRefID)
			relatedId = string(rel.RefB.ElementRefID)
		} else if isDependent(rel.Relationship) || isPackageOf(rel.Relationship) {
			foundId = string(rel.RefB.ElementRefID)
			relatedId = string(rel.RefA.ElementRefID)
		} else {
			continue
		}

		foundPackNodes := s.packagePackages[foundId]
		foundFileNodes := s.filePackages[foundId]
		relatedPackNodes := s.packagePackages[relatedId]
		relatedFileNodes := s.filePackages[relatedId]

		justification := getJustification(rel)

		for _, packNode := range foundPackNodes {
			p, err := common.GetIsDep(packNode, relatedPackNodes, relatedFileNodes, justification, model.DependencyTypeUnknown)
			if err != nil {
				logger.Errorf("error generating spdx edge %v", err)
				continue
			}
			if p != nil {
				preds.IsDependency = append(preds.IsDependency, *p)
			}
		}
		for _, fileNode := range foundFileNodes {
			p, err := common.GetIsDep(fileNode, relatedPackNodes, relatedFileNodes, justification, model.DependencyTypeUnknown)
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

	lv := s.spdxDoc.CreationInfo.LicenseListVersion
	if lv == "" {
		lv = "UNKNOWN"
	}
	for id, cls := range s.packageLegals {
		for _, cl := range cls {

			modifiedDecLicense := common.FixSPDXLicenseExpression(cl.DeclaredLicense, s.licenseInLine)
			modifiedDisLicense := common.FixSPDXLicenseExpression(cl.DiscoveredLicense, s.licenseInLine)

			cl.DeclaredLicense = modifiedDecLicense
			cl.DiscoveredLicense = modifiedDisLicense

			dec := common.ParseLicenses(modifiedDecLicense, &lv, s.licenseInLine)
			dis := common.ParseLicenses(modifiedDisLicense, &lv, s.licenseInLine)
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

	for _, pkg := range s.spdxDoc.Packages {
		pkgInputSpecs := s.packagePackages[string(pkg.PackageSPDXIdentifier)]
		for _, extRef := range pkg.PackageExternalReferences {
			if extRef.Category == spdx_common.CategorySecurity {
				locator := extRef.Locator
				metadataInputSpec := &model.HasMetadataInputSpec{
					Key:           "cpe",
					Value:         locator,
					Timestamp:     time.Now().UTC(),
					Justification: "spdx cpe external reference",
					Origin:        "GUAC SPDX",
					Collector:     "GUAC",
				}
				for i := range pkgInputSpecs {
					hasMetadata := assembler.HasMetadataIngest{
						Pkg:          pkgInputSpecs[i],
						PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
						HasMetadata:  metadataInputSpec,
					}
					preds.HasMetadata = append(preds.HasMetadata, hasMetadata)
				}
			}
		}
	}

	return preds
}

func isDependency(rel string) bool {
	return map[string]bool{
		spdx_common.TypeRelationshipContains:      true,
		spdx_common.TypeRelationshipDependsOn:     true,
		spdx_common.TypeRelationshipGeneratedFrom: true,
	}[rel]
}

func isDependent(rel string) bool {
	return map[string]bool{
		spdx_common.TypeRelationshipContainedBy:  true,
		spdx_common.TypeRelationshipDependencyOf: true,
		spdx_common.TypeRelationshipGenerates:    true,
	}[rel]
}

func isPackageOf(rel string) bool {
	return map[string]bool{
		spdx_common.TypeRelationshipPackageOf: true,
	}[rel]
}

func (s *spdxParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (s *spdxParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	// filter our duplicate identifiers
	common.RemoveDuplicateIdentifiers(s.identifierStrings)
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
		// sha224 empty file
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f": true,
		// sha384 empty file
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b": true,
		// sha512 empty file
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": true,
		// MD5 empty file
		"d41d8cd98f00b204e9800998ecf8427e": true,
		// ADLER32 empty file
		"00000001": true,
		// SHA3-256 empty file
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a": true,
		// SHA3-384 empty file
		"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004": true,
		// SHA3-512 empty file
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26": true,
		// BLAKE2b-256 empty file
		"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8": true,
		// BLAKE2b-384 empty file
		"b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100": true,
		// BLAKE2b-512 empty file
		"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce": true,
		// TODO: add the same for other SPDX hash algorithms available
		// ref: https://github.com/guacsec/guac/issues/1229
	}[v]
}
