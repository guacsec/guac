// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
)

func (a *Artifact) Occurrences(ctx context.Context) (result []*Occurrence, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedOccurrences(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.OccurrencesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryOccurrences().All(ctx)
	}
	return result, err
}

func (a *Artifact) Sbom(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedSbom(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.SbomOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QuerySbom().All(ctx)
	}
	return result, err
}

func (a *Artifact) Attestations(ctx context.Context) (result []*SLSAAttestation, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedAttestations(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.AttestationsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryAttestations().All(ctx)
	}
	return result, err
}

func (a *Artifact) AttestationsSubject(ctx context.Context) (result []*SLSAAttestation, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedAttestationsSubject(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.AttestationsSubjectOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryAttestationsSubject().All(ctx)
	}
	return result, err
}

func (a *Artifact) HashEqualArtA(ctx context.Context) (result []*HashEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedHashEqualArtA(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.HashEqualArtAOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryHashEqualArtA().All(ctx)
	}
	return result, err
}

func (a *Artifact) HashEqualArtB(ctx context.Context) (result []*HashEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedHashEqualArtB(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.HashEqualArtBOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryHashEqualArtB().All(ctx)
	}
	return result, err
}

func (a *Artifact) Vex(ctx context.Context) (result []*CertifyVex, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedVex(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.VexOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryVex().All(ctx)
	}
	return result, err
}

func (a *Artifact) Certification(ctx context.Context) (result []*Certification, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedCertification(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.CertificationOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryCertification().All(ctx)
	}
	return result, err
}

func (a *Artifact) Metadata(ctx context.Context) (result []*HasMetadata, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedMetadata(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.MetadataOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryMetadata().All(ctx)
	}
	return result, err
}

func (a *Artifact) Poc(ctx context.Context) (result []*PointOfContact, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedPoc(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.PocOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryPoc().All(ctx)
	}
	return result, err
}

func (a *Artifact) IncludedInSboms(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = a.NamedIncludedInSboms(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = a.Edges.IncludedInSbomsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = a.QueryIncludedInSboms().All(ctx)
	}
	return result, err
}

func (bom *BillOfMaterials) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := bom.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = bom.QueryPackage().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (bom *BillOfMaterials) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := bom.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = bom.QueryArtifact().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (bom *BillOfMaterials) IncludedSoftwarePackages(ctx context.Context) (result []*PackageVersion, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = bom.NamedIncludedSoftwarePackages(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = bom.Edges.IncludedSoftwarePackagesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = bom.QueryIncludedSoftwarePackages().All(ctx)
	}
	return result, err
}

func (bom *BillOfMaterials) IncludedSoftwareArtifacts(ctx context.Context) (result []*Artifact, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = bom.NamedIncludedSoftwareArtifacts(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = bom.Edges.IncludedSoftwareArtifactsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = bom.QueryIncludedSoftwareArtifacts().All(ctx)
	}
	return result, err
}

func (bom *BillOfMaterials) IncludedDependencies(ctx context.Context) (result []*Dependency, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = bom.NamedIncludedDependencies(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = bom.Edges.IncludedDependenciesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = bom.QueryIncludedDependencies().All(ctx)
	}
	return result, err
}

func (bom *BillOfMaterials) IncludedOccurrences(ctx context.Context) (result []*Occurrence, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = bom.NamedIncludedOccurrences(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = bom.Edges.IncludedOccurrencesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = bom.QueryIncludedOccurrences().All(ctx)
	}
	return result, err
}

func (b *Builder) SlsaAttestations(ctx context.Context) (result []*SLSAAttestation, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = b.NamedSlsaAttestations(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = b.Edges.SlsaAttestationsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = b.QuerySlsaAttestations().All(ctx)
	}
	return result, err
}

func (c *Certification) Source(ctx context.Context) (*SourceName, error) {
	result, err := c.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = c.QuerySource().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (c *Certification) PackageVersion(ctx context.Context) (*PackageVersion, error) {
	result, err := c.Edges.PackageVersionOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryPackageVersion().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (c *Certification) AllVersions(ctx context.Context) (*PackageName, error) {
	result, err := c.Edges.AllVersionsOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryAllVersions().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (c *Certification) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := c.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryArtifact().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (cl *CertifyLegal) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := cl.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = cl.QueryPackage().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (cl *CertifyLegal) Source(ctx context.Context) (*SourceName, error) {
	result, err := cl.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = cl.QuerySource().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (cl *CertifyLegal) DeclaredLicenses(ctx context.Context) (result []*License, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = cl.NamedDeclaredLicenses(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = cl.Edges.DeclaredLicensesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = cl.QueryDeclaredLicenses().All(ctx)
	}
	return result, err
}

func (cl *CertifyLegal) DiscoveredLicenses(ctx context.Context) (result []*License, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = cl.NamedDiscoveredLicenses(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = cl.Edges.DiscoveredLicensesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = cl.QueryDiscoveredLicenses().All(ctx)
	}
	return result, err
}

func (cs *CertifyScorecard) Source(ctx context.Context) (*SourceName, error) {
	result, err := cs.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = cs.QuerySource().Only(ctx)
	}
	return result, err
}

func (cv *CertifyVex) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := cv.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = cv.QueryPackage().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (cv *CertifyVex) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := cv.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = cv.QueryArtifact().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (cv *CertifyVex) Vulnerability(ctx context.Context) (*VulnerabilityID, error) {
	result, err := cv.Edges.VulnerabilityOrErr()
	if IsNotLoaded(err) {
		result, err = cv.QueryVulnerability().Only(ctx)
	}
	return result, err
}

func (cv *CertifyVuln) Vulnerability(ctx context.Context) (*VulnerabilityID, error) {
	result, err := cv.Edges.VulnerabilityOrErr()
	if IsNotLoaded(err) {
		result, err = cv.QueryVulnerability().Only(ctx)
	}
	return result, err
}

func (cv *CertifyVuln) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := cv.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = cv.QueryPackage().Only(ctx)
	}
	return result, err
}

func (d *Dependency) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := d.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryPackage().Only(ctx)
	}
	return result, err
}

func (d *Dependency) DependentPackageName(ctx context.Context) (*PackageName, error) {
	result, err := d.Edges.DependentPackageNameOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryDependentPackageName().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (d *Dependency) DependentPackageVersion(ctx context.Context) (*PackageVersion, error) {
	result, err := d.Edges.DependentPackageVersionOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryDependentPackageVersion().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (d *Dependency) IncludedInSboms(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = d.NamedIncludedInSboms(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = d.Edges.IncludedInSbomsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = d.QueryIncludedInSboms().All(ctx)
	}
	return result, err
}

func (hm *HasMetadata) Source(ctx context.Context) (*SourceName, error) {
	result, err := hm.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = hm.QuerySource().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hm *HasMetadata) PackageVersion(ctx context.Context) (*PackageVersion, error) {
	result, err := hm.Edges.PackageVersionOrErr()
	if IsNotLoaded(err) {
		result, err = hm.QueryPackageVersion().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hm *HasMetadata) AllVersions(ctx context.Context) (*PackageName, error) {
	result, err := hm.Edges.AllVersionsOrErr()
	if IsNotLoaded(err) {
		result, err = hm.QueryAllVersions().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hm *HasMetadata) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := hm.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = hm.QueryArtifact().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hsa *HasSourceAt) PackageVersion(ctx context.Context) (*PackageVersion, error) {
	result, err := hsa.Edges.PackageVersionOrErr()
	if IsNotLoaded(err) {
		result, err = hsa.QueryPackageVersion().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hsa *HasSourceAt) AllVersions(ctx context.Context) (*PackageName, error) {
	result, err := hsa.Edges.AllVersionsOrErr()
	if IsNotLoaded(err) {
		result, err = hsa.QueryAllVersions().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hsa *HasSourceAt) Source(ctx context.Context) (*SourceName, error) {
	result, err := hsa.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = hsa.QuerySource().Only(ctx)
	}
	return result, err
}

func (he *HashEqual) ArtifactA(ctx context.Context) (*Artifact, error) {
	result, err := he.Edges.ArtifactAOrErr()
	if IsNotLoaded(err) {
		result, err = he.QueryArtifactA().Only(ctx)
	}
	return result, err
}

func (he *HashEqual) ArtifactB(ctx context.Context) (*Artifact, error) {
	result, err := he.Edges.ArtifactBOrErr()
	if IsNotLoaded(err) {
		result, err = he.QueryArtifactB().Only(ctx)
	}
	return result, err
}

func (l *License) DeclaredInCertifyLegals(ctx context.Context) (result []*CertifyLegal, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = l.NamedDeclaredInCertifyLegals(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = l.Edges.DeclaredInCertifyLegalsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = l.QueryDeclaredInCertifyLegals().All(ctx)
	}
	return result, err
}

func (l *License) DiscoveredInCertifyLegals(ctx context.Context) (result []*CertifyLegal, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = l.NamedDiscoveredInCertifyLegals(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = l.Edges.DiscoveredInCertifyLegalsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = l.QueryDiscoveredInCertifyLegals().All(ctx)
	}
	return result, err
}

func (o *Occurrence) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := o.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = o.QueryArtifact().Only(ctx)
	}
	return result, err
}

func (o *Occurrence) Package(ctx context.Context) (*PackageVersion, error) {
	result, err := o.Edges.PackageOrErr()
	if IsNotLoaded(err) {
		result, err = o.QueryPackage().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (o *Occurrence) Source(ctx context.Context) (*SourceName, error) {
	result, err := o.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = o.QuerySource().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (o *Occurrence) IncludedInSboms(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = o.NamedIncludedInSboms(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = o.Edges.IncludedInSbomsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = o.QueryIncludedInSboms().All(ctx)
	}
	return result, err
}

func (pn *PackageName) Versions(ctx context.Context) (result []*PackageVersion, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedVersions(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.VersionsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryVersions().All(ctx)
	}
	return result, err
}

func (pn *PackageName) HasSourceAt(ctx context.Context) (result []*HasSourceAt, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedHasSourceAt(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.HasSourceAtOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryHasSourceAt().All(ctx)
	}
	return result, err
}

func (pn *PackageName) Dependency(ctx context.Context) (result []*Dependency, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedDependency(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.DependencyOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryDependency().All(ctx)
	}
	return result, err
}

func (pn *PackageName) Certification(ctx context.Context) (result []*Certification, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedCertification(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.CertificationOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryCertification().All(ctx)
	}
	return result, err
}

func (pn *PackageName) Metadata(ctx context.Context) (result []*HasMetadata, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedMetadata(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.MetadataOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryMetadata().All(ctx)
	}
	return result, err
}

func (pn *PackageName) Poc(ctx context.Context) (result []*PointOfContact, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pn.NamedPoc(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pn.Edges.PocOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pn.QueryPoc().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Name(ctx context.Context) (*PackageName, error) {
	result, err := pv.Edges.NameOrErr()
	if IsNotLoaded(err) {
		result, err = pv.QueryName().Only(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Occurrences(ctx context.Context) (result []*Occurrence, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedOccurrences(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.OccurrencesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryOccurrences().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Sbom(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedSbom(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.SbomOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QuerySbom().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Vuln(ctx context.Context) (result []*CertifyVuln, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedVuln(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.VulnOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryVuln().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Vex(ctx context.Context) (result []*CertifyVex, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedVex(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.VexOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryVex().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) HasSourceAt(ctx context.Context) (result []*HasSourceAt, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedHasSourceAt(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.HasSourceAtOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryHasSourceAt().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Certification(ctx context.Context) (result []*Certification, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedCertification(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.CertificationOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryCertification().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Metadata(ctx context.Context) (result []*HasMetadata, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedMetadata(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.MetadataOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryMetadata().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Dependency(ctx context.Context) (result []*Dependency, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedDependency(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.DependencyOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryDependency().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) DependencySubject(ctx context.Context) (result []*Dependency, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedDependencySubject(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.DependencySubjectOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryDependencySubject().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) IncludedInSboms(ctx context.Context) (result []*BillOfMaterials, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedIncludedInSboms(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.IncludedInSbomsOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryIncludedInSboms().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) PkgEqualPkgA(ctx context.Context) (result []*PkgEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedPkgEqualPkgA(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.PkgEqualPkgAOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryPkgEqualPkgA().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) PkgEqualPkgB(ctx context.Context) (result []*PkgEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedPkgEqualPkgB(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.PkgEqualPkgBOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryPkgEqualPkgB().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) Poc(ctx context.Context) (result []*PointOfContact, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedPoc(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.PocOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryPoc().All(ctx)
	}
	return result, err
}

func (pv *PackageVersion) CertifyLegal(ctx context.Context) (result []*CertifyLegal, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = pv.NamedCertifyLegal(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = pv.Edges.CertifyLegalOrErr()
	}
	if IsNotLoaded(err) {
		result, err = pv.QueryCertifyLegal().All(ctx)
	}
	return result, err
}

func (pe *PkgEqual) PackageA(ctx context.Context) (*PackageVersion, error) {
	result, err := pe.Edges.PackageAOrErr()
	if IsNotLoaded(err) {
		result, err = pe.QueryPackageA().Only(ctx)
	}
	return result, err
}

func (pe *PkgEqual) PackageB(ctx context.Context) (*PackageVersion, error) {
	result, err := pe.Edges.PackageBOrErr()
	if IsNotLoaded(err) {
		result, err = pe.QueryPackageB().Only(ctx)
	}
	return result, err
}

func (poc *PointOfContact) Source(ctx context.Context) (*SourceName, error) {
	result, err := poc.Edges.SourceOrErr()
	if IsNotLoaded(err) {
		result, err = poc.QuerySource().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (poc *PointOfContact) PackageVersion(ctx context.Context) (*PackageVersion, error) {
	result, err := poc.Edges.PackageVersionOrErr()
	if IsNotLoaded(err) {
		result, err = poc.QueryPackageVersion().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (poc *PointOfContact) AllVersions(ctx context.Context) (*PackageName, error) {
	result, err := poc.Edges.AllVersionsOrErr()
	if IsNotLoaded(err) {
		result, err = poc.QueryAllVersions().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (poc *PointOfContact) Artifact(ctx context.Context) (*Artifact, error) {
	result, err := poc.Edges.ArtifactOrErr()
	if IsNotLoaded(err) {
		result, err = poc.QueryArtifact().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (sa *SLSAAttestation) BuiltFrom(ctx context.Context) (result []*Artifact, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = sa.NamedBuiltFrom(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = sa.Edges.BuiltFromOrErr()
	}
	if IsNotLoaded(err) {
		result, err = sa.QueryBuiltFrom().All(ctx)
	}
	return result, err
}

func (sa *SLSAAttestation) BuiltBy(ctx context.Context) (*Builder, error) {
	result, err := sa.Edges.BuiltByOrErr()
	if IsNotLoaded(err) {
		result, err = sa.QueryBuiltBy().Only(ctx)
	}
	return result, err
}

func (sa *SLSAAttestation) Subject(ctx context.Context) (*Artifact, error) {
	result, err := sa.Edges.SubjectOrErr()
	if IsNotLoaded(err) {
		result, err = sa.QuerySubject().Only(ctx)
	}
	return result, err
}

func (sn *SourceName) Occurrences(ctx context.Context) (result []*Occurrence, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = sn.NamedOccurrences(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = sn.Edges.OccurrencesOrErr()
	}
	if IsNotLoaded(err) {
		result, err = sn.QueryOccurrences().All(ctx)
	}
	return result, err
}

func (ve *VulnEqual) VulnerabilityA(ctx context.Context) (*VulnerabilityID, error) {
	result, err := ve.Edges.VulnerabilityAOrErr()
	if IsNotLoaded(err) {
		result, err = ve.QueryVulnerabilityA().Only(ctx)
	}
	return result, err
}

func (ve *VulnEqual) VulnerabilityB(ctx context.Context) (*VulnerabilityID, error) {
	result, err := ve.Edges.VulnerabilityBOrErr()
	if IsNotLoaded(err) {
		result, err = ve.QueryVulnerabilityB().Only(ctx)
	}
	return result, err
}

func (vi *VulnerabilityID) VulnEqualVulnA(ctx context.Context) (result []*VulnEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = vi.NamedVulnEqualVulnA(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = vi.Edges.VulnEqualVulnAOrErr()
	}
	if IsNotLoaded(err) {
		result, err = vi.QueryVulnEqualVulnA().All(ctx)
	}
	return result, err
}

func (vi *VulnerabilityID) VulnEqualVulnB(ctx context.Context) (result []*VulnEqual, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = vi.NamedVulnEqualVulnB(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = vi.Edges.VulnEqualVulnBOrErr()
	}
	if IsNotLoaded(err) {
		result, err = vi.QueryVulnEqualVulnB().All(ctx)
	}
	return result, err
}

func (vi *VulnerabilityID) VulnerabilityMetadata(ctx context.Context) (result []*VulnerabilityMetadata, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = vi.NamedVulnerabilityMetadata(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = vi.Edges.VulnerabilityMetadataOrErr()
	}
	if IsNotLoaded(err) {
		result, err = vi.QueryVulnerabilityMetadata().All(ctx)
	}
	return result, err
}

func (vi *VulnerabilityID) VexPackage(ctx context.Context) (result []*CertifyVex, err error) {
	if fc := graphql.GetFieldContext(ctx); fc != nil && fc.Field.Alias != "" {
		result, err = vi.NamedVexPackage(graphql.GetFieldContext(ctx).Field.Alias)
	} else {
		result, err = vi.Edges.VexPackageOrErr()
	}
	if IsNotLoaded(err) {
		result, err = vi.QueryVexPackage().All(ctx)
	}
	return result, err
}

func (vm *VulnerabilityMetadata) VulnerabilityID(ctx context.Context) (*VulnerabilityID, error) {
	result, err := vm.Edges.VulnerabilityIDOrErr()
	if IsNotLoaded(err) {
		result, err = vm.QueryVulnerabilityID().Only(ctx)
	}
	return result, err
}
