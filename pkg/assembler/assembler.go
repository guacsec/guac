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

package assembler

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

type assembler struct{} //nolint: unused

// IngestPredicates contains the set of predicates that want to be
// ingested based on the GUAC ontology. It only has evidence trees as
// ingestion of the software trees are implicit and handled by the
// client library.
// TODO: fix typo in isDepedency
type IngestPredicates struct {
	CertifyScorecard []CertifyScorecardIngest `json:"certifyScorecard,omitempty"`
	IsDependency     []IsDependencyIngest     `json:"isDependency,omitempty"`
	IsOccurrence     []IsOccurrenceIngest     `json:"isOccurrence,omitempty"`
	HasSlsa          []HasSlsaIngest          `json:"hasSlsa,omitempty"`
	CertifyVuln      []CertifyVulnIngest      `json:"certifyVuln,omitempty"`
	VulnEqual        []VulnEqualIngest        `json:"vulnEqual,omitempty"`
	HasSourceAt      []HasSourceAtIngest      `json:"hasSourceAt,omitempty"`
	CertifyBad       []CertifyBadIngest       `json:"certifyBad,omitempty"`
	CertifyGood      []CertifyGoodIngest      `json:"certifyGood,omitempty"`
	HasSBOM          []HasSBOMIngest          `json:"hasSBOM,omitempty"`
	HashEqual        []HashEqualIngest        `json:"hashEqual,omitempty"`
	PkgEqual         []PkgEqualIngest         `json:"pkgEqual,omitempty"`
	Vex              []VexIngest              `json:"vex,omitempty"`
	PointOfContact   []PointOfContactIngest   `json:"contact,omitempty"`
	VulnMetadata     []VulnMetadataIngest     `json:"vulnMetadata,omitempty"`
	HasMetadata      []HasMetadataIngest      `json:"hasMetadata,omitempty"`
	CertifyLegal     []CertifyLegalIngest     `json:"certifyLegal,omitempty"`
}

type CertifyScorecardIngest struct {
	Source    *generated.SourceInputSpec    `json:"source,omitempty"`
	Scorecard *generated.ScorecardInputSpec `json:"scorecard,omitempty"`
}

type IsDependencyIngest struct {
	Pkg             *generated.PkgInputSpec          `json:"pkg,omitempty"`
	DepPkg          *generated.PkgInputSpec          `json:"depPkg,omitempty"`
	DepPkgMatchFlag generated.MatchFlags             `json:"depPkgMatchFlag,omitempty"`
	IsDependency    *generated.IsDependencyInputSpec `json:"isDependency,omitempty"`
}

type IsOccurrenceIngest struct {
	// Occurrence describes either pkg or src
	Pkg *generated.PkgInputSpec    `json:"pkg,omitempty"`
	Src *generated.SourceInputSpec `json:"src,omitempty"`

	// Artifact is the required object of the occurence
	Artifact *generated.ArtifactInputSpec `json:"artifact,omitempty"`

	IsOccurrence *generated.IsOccurrenceInputSpec `json:"isOccurrence,omitempty"`
}

type HasSlsaIngest struct {
	Artifact  *generated.ArtifactInputSpec  `json:",omitempty"`
	HasSlsa   *generated.SLSAInputSpec      `json:",omitempty"`
	Materials []generated.ArtifactInputSpec `json:",omitempty"`
	Builder   *generated.BuilderInputSpec   `json:",omitempty"`

	// Upon more investigation, seems like SLSA should
	// only be applied to an artifact and linkages to pkg
	// or src should be done via IsOccurrence
	// Pkg      *generated.PkgInputSpec
	// Src      *generated.SourceInputSpec
}

type CertifyVulnIngest struct {
	// pkg is required
	Pkg *generated.PkgInputSpec `json:"pkg,omitempty"`

	// vulnerability or noVuln if no vulnerability is found
	Vulnerability *generated.VulnerabilityInputSpec `json:"vulnerability,omitempty"`

	VulnData *generated.ScanMetadataInput `json:"vulnData,omitempty"`
}

type VulnEqualIngest struct {
	Vulnerability      *generated.VulnerabilityInputSpec `json:"vulnerability,omitempty"`
	EqualVulnerability *generated.VulnerabilityInputSpec `json:"equalVulnerability,omitempty"`
	VulnEqual          *generated.VulnEqualInputSpec     `json:"vulnEqual,omitempty"`
}

type VulnMetadataIngest struct {
	// vulnerability (cannot be set to noVuln)
	Vulnerability *generated.VulnerabilityInputSpec         `json:"vulnerability,omitempty"`
	VulnMetadata  *generated.VulnerabilityMetadataInputSpec `json:"vulnData,omitempty"`
}

type HasSourceAtIngest struct {
	Pkg          *generated.PkgInputSpec         `json:"pkg,omitempty"`
	PkgMatchFlag generated.MatchFlags            `json:"pkgMatchFlag,omitempty"`
	Src          *generated.SourceInputSpec      `json:"src,omitempty"`
	HasSourceAt  *generated.HasSourceAtInputSpec `json:"hasSourceAt,omitempty"`
}

type HasMetadataIngest struct {
	// hasMetadata describes either pkg, src or artifact metadata
	Pkg          *generated.PkgInputSpec         `json:"pkg,omitempty"`
	PkgMatchFlag generated.MatchFlags            `json:"pkgMatchFlag,omitempty"`
	Src          *generated.SourceInputSpec      `json:"src,omitempty"`
	Artifact     *generated.ArtifactInputSpec    `json:"artifact,omitempty"`
	HasMetadata  *generated.HasMetadataInputSpec `json:"hasMetadata,omitempty"`
}

type CertifyBadIngest struct {
	// certifyBad describes either pkg, src or artifact
	Pkg          *generated.PkgInputSpec        `json:"pkg,omitempty"`
	PkgMatchFlag generated.MatchFlags           `json:"pkgMatchFlag,omitempty"`
	Src          *generated.SourceInputSpec     `json:"src,omitempty"`
	Artifact     *generated.ArtifactInputSpec   `json:"artifact,omitempty"`
	CertifyBad   *generated.CertifyBadInputSpec `json:"certifyBad,omitempty"`
}

type CertifyGoodIngest struct {
	// certifyGood describes either pkg, src or artifact
	Pkg          *generated.PkgInputSpec         `json:"pkg,omitempty"`
	PkgMatchFlag generated.MatchFlags            `json:"pkgMatchFlag,omitempty"`
	Src          *generated.SourceInputSpec      `json:"src,omitempty"`
	Artifact     *generated.ArtifactInputSpec    `json:"artifact,omitempty"`
	CertifyGood  *generated.CertifyGoodInputSpec `json:"certifyGood,omitempty"`
}

type HasSBOMIngest struct {
	// hasSBOM describes either pkg or artifact
	Pkg      *generated.PkgInputSpec      `json:"pkg,omitempty"`
	Artifact *generated.ArtifactInputSpec `json:"artifact,omitempty"`

	HasSBOM  *generated.HasSBOMInputSpec         `json:"hasSbom,omitempty"`
	Includes *generated.HasSBOMIncludesInputSpec `json:"includes,omitempty"`
}

type VexIngest struct {
	// pkg or artifact is required
	Pkg      *generated.PkgInputSpec      `json:"pkg,omitempty"`
	Artifact *generated.ArtifactInputSpec `json:"artifact,omitempty"`

	// vulnerability (cannot be set to noVuln)
	Vulnerability *generated.VulnerabilityInputSpec `json:"vulnerability,omitempty"`

	VexData *generated.VexStatementInputSpec `json:"vexData,omitempty"`
}

type PointOfContactIngest struct {
	// pointOfContact describes either pkg, src or artifact
	Pkg            *generated.PkgInputSpec            `json:"pkg,omitempty"`
	PkgMatchFlag   generated.MatchFlags               `json:"pkgMatchFlag,omitempty"`
	Src            *generated.SourceInputSpec         `json:"src,omitempty"`
	Artifact       *generated.ArtifactInputSpec       `json:"artifact,omitempty"`
	PointOfContact *generated.PointOfContactInputSpec `json:"pointOfContact,omitempty"`
}

type HashEqualIngest struct {
	// HashEqualIngest describes two artifacts are the same
	Artifact      *generated.ArtifactInputSpec `json:"artifact,omitempty"`
	EqualArtifact *generated.ArtifactInputSpec `json:"equalArtifact,omitempty"`

	HashEqual *generated.HashEqualInputSpec `json:"hashEqual,omitempty"`
}

type PkgEqualIngest struct {
	// PkgEqualIngest describes two packages are the same
	Pkg      *generated.PkgInputSpec      `json:"pkg,omitempty"`
	EqualPkg *generated.PkgInputSpec      `json:"equalPkg,omitempty"`
	PkgEqual *generated.PkgEqualInputSpec `json:"pkgEqual,omitempty"`
}

type CertifyLegalIngest struct {
	Pkg *generated.PkgInputSpec    `json:"pkg,omitempty"`
	Src *generated.SourceInputSpec `json:"src,omitempty"`

	Declared   []generated.LicenseInputSpec `json:"declared,omitempty"`
	Discovered []generated.LicenseInputSpec `json:"discovered,omitempty"`

	CertifyLegal *generated.CertifyLegalInputSpec `json:"certifyLegal,omitempty"`
}

func (i IngestPredicates) GetPackages(ctx context.Context) map[string]*generated.IDorPkgInput {
	packageMap := make(map[string]*generated.IDorPkgInput)
	for _, dep := range i.IsDependency {
		if dep.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(dep.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: dep.Pkg}
			}
		}
		if dep.DepPkg != nil {
			depPkgPurl := helpers.PkgInputSpecToPurl(dep.DepPkg)
			if _, ok := packageMap[depPkgPurl]; !ok {
				packageMap[depPkgPurl] = &generated.IDorPkgInput{PackageInput: dep.DepPkg}
			}
		}
	}
	for _, occur := range i.IsOccurrence {
		if occur.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(occur.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: occur.Pkg}
			}
		}
	}
	for _, vuln := range i.CertifyVuln {
		if vuln.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(vuln.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: vuln.Pkg}
			}
		}
	}
	for _, hasSource := range i.HasSourceAt {
		if hasSource.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(hasSource.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: hasSource.Pkg}
			}
		}
	}
	for _, bad := range i.CertifyBad {
		if bad.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(bad.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: bad.Pkg}
			}
		}
	}
	for _, good := range i.CertifyGood {
		if good.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(good.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: good.Pkg}
			}
		}
	}
	for _, sbom := range i.HasSBOM {
		if sbom.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(sbom.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: sbom.Pkg}
			}
		}
	}
	for _, v := range i.Vex {
		if v.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(v.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: v.Pkg}
			}
		}
	}
	for _, poc := range i.PointOfContact {
		if poc.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(poc.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: poc.Pkg}
			}
		}
	}
	for _, hm := range i.HasMetadata {
		if hm.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(hm.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: hm.Pkg}
			}
		}
	}
	for _, equal := range i.PkgEqual {
		if equal.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(equal.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: equal.Pkg}
			}
		}
		if equal.EqualPkg != nil {
			equalPkgPurl := helpers.PkgInputSpecToPurl(equal.EqualPkg)
			if _, ok := packageMap[equalPkgPurl]; !ok {
				packageMap[equalPkgPurl] = &generated.IDorPkgInput{PackageInput: equal.EqualPkg}
			}
		}
	}
	for _, cl := range i.CertifyLegal {
		if cl.Pkg != nil {
			pkgPurl := helpers.PkgInputSpecToPurl(cl.Pkg)
			if _, ok := packageMap[pkgPurl]; !ok {
				packageMap[pkgPurl] = &generated.IDorPkgInput{PackageInput: cl.Pkg}
			}
		}
	}

	return packageMap
}

func (i IngestPredicates) GetSources(ctx context.Context) map[string]*generated.IDorSourceInput {
	sourceMap := make(map[string]*generated.IDorSourceInput)
	for _, score := range i.CertifyScorecard {
		if score.Source != nil {
			sourceString := helpers.ConcatenateSourceInput(score.Source)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: score.Source}
			}
		}
	}
	for _, occur := range i.IsOccurrence {
		if occur.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(occur.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: occur.Src}
			}
		}
	}
	for _, hasSource := range i.HasSourceAt {
		if hasSource.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(hasSource.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: hasSource.Src}
			}
		}
	}
	for _, bad := range i.CertifyBad {
		if bad.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(bad.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: bad.Src}
			}
		}
	}
	for _, good := range i.CertifyGood {
		if good.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(good.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: good.Src}
			}
		}
	}
	for _, poc := range i.PointOfContact {
		if poc.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(poc.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: poc.Src}
			}
		}
	}
	for _, hm := range i.HasMetadata {
		if hm.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(hm.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: hm.Src}
			}
		}
	}
	for _, cl := range i.CertifyLegal {
		if cl.Src != nil {
			sourceString := helpers.ConcatenateSourceInput(cl.Src)
			if _, ok := sourceMap[sourceString]; !ok {
				sourceMap[sourceString] = &generated.IDorSourceInput{SourceInput: cl.Src}
			}
		}
	}

	return sourceMap
}

func (i IngestPredicates) GetArtifacts(ctx context.Context) map[string]*generated.IDorArtifactInput {
	artifactMap := make(map[string]*generated.IDorArtifactInput)
	for _, occur := range i.IsOccurrence {
		if occur.Artifact != nil {
			artifactString := helpers.ArtifactKey(occur.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: occur.Artifact}
			}
		}
	}
	for _, slsa := range i.HasSlsa {
		if slsa.Artifact != nil {
			artifactString := helpers.ArtifactKey(slsa.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: slsa.Artifact}
			}
		}
	}
	for _, sbom := range i.HasSBOM {
		if sbom.Artifact != nil {
			artifactString := helpers.ArtifactKey(sbom.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: sbom.Artifact}
			}
		}
	}
	for _, bad := range i.CertifyBad {
		if bad.Artifact != nil {
			artifactString := helpers.ArtifactKey(bad.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: bad.Artifact}
			}
		}
	}
	for _, good := range i.CertifyGood {
		if good.Artifact != nil {
			artifactString := helpers.ArtifactKey(good.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: good.Artifact}
			}
		}
	}
	for _, v := range i.Vex {
		if v.Artifact != nil {
			artifactString := helpers.ArtifactKey(v.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: v.Artifact}
			}
		}
	}
	for _, poc := range i.PointOfContact {
		if poc.Artifact != nil {
			artifactString := helpers.ArtifactKey(poc.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: poc.Artifact}
			}
		}
	}
	for _, hm := range i.HasMetadata {
		if hm.Artifact != nil {
			artifactString := helpers.ArtifactKey(hm.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: hm.Artifact}
			}
		}
	}
	for _, equal := range i.HashEqual {
		if equal.Artifact != nil {
			artifactString := helpers.ArtifactKey(equal.Artifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: equal.Artifact}
			}
		}
		if equal.EqualArtifact != nil {
			artifactString := helpers.ArtifactKey(equal.EqualArtifact)
			if _, ok := artifactMap[artifactString]; !ok {
				artifactMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: equal.EqualArtifact}
			}
		}
	}

	return artifactMap
}

func (i IngestPredicates) GetMaterials(ctx context.Context) map[string]*generated.IDorArtifactInput {
	materialMap := make(map[string]*generated.IDorArtifactInput)
	for _, slsa := range i.HasSlsa {
		for _, mat := range slsa.Materials {
			artifactString := mat.Algorithm + ":" + mat.Digest
			if _, ok := materialMap[artifactString]; !ok {
				materialMap[artifactString] = &generated.IDorArtifactInput{ArtifactInput: &mat}
			}
		}

	}

	return materialMap
}

func (i IngestPredicates) GetBuilders(ctx context.Context) map[string]*generated.IDorBuilderInput {
	builderMap := make(map[string]*generated.IDorBuilderInput)
	for _, slsa := range i.HasSlsa {
		if slsa.Builder != nil {
			if _, ok := builderMap[slsa.Builder.Uri]; !ok {
				builderMap[slsa.Builder.Uri] = &generated.IDorBuilderInput{BuilderInput: slsa.Builder}
			}
		}
	}
	return builderMap
}

func (i IngestPredicates) GetVulnerabilities(ctx context.Context) map[string]*generated.IDorVulnerabilityInput {
	vulnMap := make(map[string]*generated.IDorVulnerabilityInput)
	for _, v := range i.CertifyVuln {
		equalVURI := helpers.VulnInputToVURI(v.Vulnerability)
		if _, ok := vulnMap[equalVURI]; !ok {
			vulnMap[equalVURI] = &generated.IDorVulnerabilityInput{VulnerabilityInput: v.Vulnerability}
		}
	}
	for _, v := range i.VulnMetadata {
		equalVURI := helpers.VulnInputToVURI(v.Vulnerability)
		if _, ok := vulnMap[equalVURI]; !ok {
			vulnMap[equalVURI] = &generated.IDorVulnerabilityInput{VulnerabilityInput: v.Vulnerability}
		}

	}
	for _, v := range i.VulnEqual {
		if v.Vulnerability != nil {
			equalVURI := helpers.VulnInputToVURI(v.Vulnerability)
			if _, ok := vulnMap[equalVURI]; !ok {
				vulnMap[equalVURI] = &generated.IDorVulnerabilityInput{VulnerabilityInput: v.Vulnerability}
			}
		}
		if v.EqualVulnerability != nil {
			equalVURI := helpers.VulnInputToVURI(v.EqualVulnerability)
			if _, ok := vulnMap[equalVURI]; !ok {
				vulnMap[equalVURI] = &generated.IDorVulnerabilityInput{VulnerabilityInput: v.EqualVulnerability}
			}
		}
	}
	for _, v := range i.Vex {
		equalVURI := helpers.VulnInputToVURI(v.Vulnerability)
		if _, ok := vulnMap[equalVURI]; !ok {
			vulnMap[equalVURI] = &generated.IDorVulnerabilityInput{VulnerabilityInput: v.Vulnerability}
		}
	}

	return vulnMap
}

func (i IngestPredicates) GetLicenses(ctx context.Context) map[string]*generated.IDorLicenseInput {
	licenseMap := make(map[string]*generated.IDorLicenseInput)
	for _, cl := range i.CertifyLegal {
		for i := range cl.Declared {
			k := helpers.LicenseKey(&cl.Declared[i])
			if _, ok := licenseMap[k]; !ok {
				licenseMap[k] = &generated.IDorLicenseInput{LicenseInput: &cl.Declared[i]}
			}
		}
		for i := range cl.Discovered {
			k := helpers.LicenseKey(&cl.Discovered[i])
			if _, ok := licenseMap[k]; !ok {
				licenseMap[k] = &generated.IDorLicenseInput{LicenseInput: &cl.Discovered[i]}
			}
		}
	}
	return licenseMap
}

// AssemblerInput represents the inputs to add to the graph
type AssemblerInput = IngestPredicates
