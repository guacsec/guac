// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hassourceat"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isvulnerability"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pointofcontact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/schema"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/scorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitymetadata"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	artifactFields := schema.Artifact{}.Fields()
	_ = artifactFields
	// artifactDescID is the schema descriptor for id field.
	artifactDescID := artifactFields[0].Descriptor()
	// artifact.DefaultID holds the default value on creation for the id field.
	artifact.DefaultID = artifactDescID.Default.(func() uuid.UUID)
	billofmaterialsFields := schema.BillOfMaterials{}.Fields()
	_ = billofmaterialsFields
	// billofmaterialsDescID is the schema descriptor for id field.
	billofmaterialsDescID := billofmaterialsFields[0].Descriptor()
	// billofmaterials.DefaultID holds the default value on creation for the id field.
	billofmaterials.DefaultID = billofmaterialsDescID.Default.(func() uuid.UUID)
	builderFields := schema.Builder{}.Fields()
	_ = builderFields
	// builderDescID is the schema descriptor for id field.
	builderDescID := builderFields[0].Descriptor()
	// builder.DefaultID holds the default value on creation for the id field.
	builder.DefaultID = builderDescID.Default.(func() uuid.UUID)
	certificationFields := schema.Certification{}.Fields()
	_ = certificationFields
	// certificationDescID is the schema descriptor for id field.
	certificationDescID := certificationFields[0].Descriptor()
	// certification.DefaultID holds the default value on creation for the id field.
	certification.DefaultID = certificationDescID.Default.(func() uuid.UUID)
	certifylegalFields := schema.CertifyLegal{}.Fields()
	_ = certifylegalFields
	// certifylegalDescID is the schema descriptor for id field.
	certifylegalDescID := certifylegalFields[0].Descriptor()
	// certifylegal.DefaultID holds the default value on creation for the id field.
	certifylegal.DefaultID = certifylegalDescID.Default.(func() uuid.UUID)
	certifyscorecardFields := schema.CertifyScorecard{}.Fields()
	_ = certifyscorecardFields
	// certifyscorecardDescID is the schema descriptor for id field.
	certifyscorecardDescID := certifyscorecardFields[0].Descriptor()
	// certifyscorecard.DefaultID holds the default value on creation for the id field.
	certifyscorecard.DefaultID = certifyscorecardDescID.Default.(func() uuid.UUID)
	certifyvexFields := schema.CertifyVex{}.Fields()
	_ = certifyvexFields
	// certifyvexDescID is the schema descriptor for id field.
	certifyvexDescID := certifyvexFields[0].Descriptor()
	// certifyvex.DefaultID holds the default value on creation for the id field.
	certifyvex.DefaultID = certifyvexDescID.Default.(func() uuid.UUID)
	certifyvulnFields := schema.CertifyVuln{}.Fields()
	_ = certifyvulnFields
	// certifyvulnDescID is the schema descriptor for id field.
	certifyvulnDescID := certifyvulnFields[0].Descriptor()
	// certifyvuln.DefaultID holds the default value on creation for the id field.
	certifyvuln.DefaultID = certifyvulnDescID.Default.(func() uuid.UUID)
	dependencyFields := schema.Dependency{}.Fields()
	_ = dependencyFields
	// dependencyDescID is the schema descriptor for id field.
	dependencyDescID := dependencyFields[0].Descriptor()
	// dependency.DefaultID holds the default value on creation for the id field.
	dependency.DefaultID = dependencyDescID.Default.(func() uuid.UUID)
	hasmetadataFields := schema.HasMetadata{}.Fields()
	_ = hasmetadataFields
	// hasmetadataDescID is the schema descriptor for id field.
	hasmetadataDescID := hasmetadataFields[0].Descriptor()
	// hasmetadata.DefaultID holds the default value on creation for the id field.
	hasmetadata.DefaultID = hasmetadataDescID.Default.(func() uuid.UUID)
	hassourceatFields := schema.HasSourceAt{}.Fields()
	_ = hassourceatFields
	// hassourceatDescID is the schema descriptor for id field.
	hassourceatDescID := hassourceatFields[0].Descriptor()
	// hassourceat.DefaultID holds the default value on creation for the id field.
	hassourceat.DefaultID = hassourceatDescID.Default.(func() uuid.UUID)
	hashequalFields := schema.HashEqual{}.Fields()
	_ = hashequalFields
	// hashequalDescID is the schema descriptor for id field.
	hashequalDescID := hashequalFields[0].Descriptor()
	// hashequal.DefaultID holds the default value on creation for the id field.
	hashequal.DefaultID = hashequalDescID.Default.(func() uuid.UUID)
	isvulnerabilityFields := schema.IsVulnerability{}.Fields()
	_ = isvulnerabilityFields
	// isvulnerabilityDescID is the schema descriptor for id field.
	isvulnerabilityDescID := isvulnerabilityFields[0].Descriptor()
	// isvulnerability.DefaultID holds the default value on creation for the id field.
	isvulnerability.DefaultID = isvulnerabilityDescID.Default.(func() uuid.UUID)
	licenseFields := schema.License{}.Fields()
	_ = licenseFields
	// licenseDescName is the schema descriptor for name field.
	licenseDescName := licenseFields[1].Descriptor()
	// license.NameValidator is a validator for the "name" field. It is called by the builders before save.
	license.NameValidator = licenseDescName.Validators[0].(func(string) error)
	// licenseDescID is the schema descriptor for id field.
	licenseDescID := licenseFields[0].Descriptor()
	// license.DefaultID holds the default value on creation for the id field.
	license.DefaultID = licenseDescID.Default.(func() uuid.UUID)
	occurrenceFields := schema.Occurrence{}.Fields()
	_ = occurrenceFields
	// occurrenceDescID is the schema descriptor for id field.
	occurrenceDescID := occurrenceFields[0].Descriptor()
	// occurrence.DefaultID holds the default value on creation for the id field.
	occurrence.DefaultID = occurrenceDescID.Default.(func() uuid.UUID)
	packagenameFields := schema.PackageName{}.Fields()
	_ = packagenameFields
	// packagenameDescType is the schema descriptor for type field.
	packagenameDescType := packagenameFields[1].Descriptor()
	// packagename.TypeValidator is a validator for the "type" field. It is called by the builders before save.
	packagename.TypeValidator = packagenameDescType.Validators[0].(func(string) error)
	// packagenameDescName is the schema descriptor for name field.
	packagenameDescName := packagenameFields[3].Descriptor()
	// packagename.NameValidator is a validator for the "name" field. It is called by the builders before save.
	packagename.NameValidator = packagenameDescName.Validators[0].(func(string) error)
	// packagenameDescID is the schema descriptor for id field.
	packagenameDescID := packagenameFields[0].Descriptor()
	// packagename.DefaultID holds the default value on creation for the id field.
	packagename.DefaultID = packagenameDescID.Default.(func() uuid.UUID)
	packageversionFields := schema.PackageVersion{}.Fields()
	_ = packageversionFields
	// packageversionDescVersion is the schema descriptor for version field.
	packageversionDescVersion := packageversionFields[2].Descriptor()
	// packageversion.DefaultVersion holds the default value on creation for the version field.
	packageversion.DefaultVersion = packageversionDescVersion.Default.(string)
	// packageversionDescSubpath is the schema descriptor for subpath field.
	packageversionDescSubpath := packageversionFields[3].Descriptor()
	// packageversion.DefaultSubpath holds the default value on creation for the subpath field.
	packageversion.DefaultSubpath = packageversionDescSubpath.Default.(string)
	// packageversionDescID is the schema descriptor for id field.
	packageversionDescID := packageversionFields[0].Descriptor()
	// packageversion.DefaultID holds the default value on creation for the id field.
	packageversion.DefaultID = packageversionDescID.Default.(func() uuid.UUID)
	pkgequalFields := schema.PkgEqual{}.Fields()
	_ = pkgequalFields
	// pkgequalDescID is the schema descriptor for id field.
	pkgequalDescID := pkgequalFields[0].Descriptor()
	// pkgequal.DefaultID holds the default value on creation for the id field.
	pkgequal.DefaultID = pkgequalDescID.Default.(func() uuid.UUID)
	pointofcontactFields := schema.PointOfContact{}.Fields()
	_ = pointofcontactFields
	// pointofcontactDescID is the schema descriptor for id field.
	pointofcontactDescID := pointofcontactFields[0].Descriptor()
	// pointofcontact.DefaultID holds the default value on creation for the id field.
	pointofcontact.DefaultID = pointofcontactDescID.Default.(func() uuid.UUID)
	slsaattestationFields := schema.SLSAAttestation{}.Fields()
	_ = slsaattestationFields
	// slsaattestationDescID is the schema descriptor for id field.
	slsaattestationDescID := slsaattestationFields[0].Descriptor()
	// slsaattestation.DefaultID holds the default value on creation for the id field.
	slsaattestation.DefaultID = slsaattestationDescID.Default.(func() uuid.UUID)
	scorecardFields := schema.Scorecard{}.Fields()
	_ = scorecardFields
	// scorecardDescAggregateScore is the schema descriptor for aggregate_score field.
	scorecardDescAggregateScore := scorecardFields[2].Descriptor()
	// scorecard.DefaultAggregateScore holds the default value on creation for the aggregate_score field.
	scorecard.DefaultAggregateScore = scorecardDescAggregateScore.Default.(float64)
	// scorecardDescTimeScanned is the schema descriptor for time_scanned field.
	scorecardDescTimeScanned := scorecardFields[3].Descriptor()
	// scorecard.DefaultTimeScanned holds the default value on creation for the time_scanned field.
	scorecard.DefaultTimeScanned = scorecardDescTimeScanned.Default.(func() time.Time)
	// scorecardDescID is the schema descriptor for id field.
	scorecardDescID := scorecardFields[0].Descriptor()
	// scorecard.DefaultID holds the default value on creation for the id field.
	scorecard.DefaultID = scorecardDescID.Default.(func() uuid.UUID)
	sourcenameFields := schema.SourceName{}.Fields()
	_ = sourcenameFields
	// sourcenameDescID is the schema descriptor for id field.
	sourcenameDescID := sourcenameFields[0].Descriptor()
	// sourcename.DefaultID holds the default value on creation for the id field.
	sourcename.DefaultID = sourcenameDescID.Default.(func() uuid.UUID)
	vulnequalFields := schema.VulnEqual{}.Fields()
	_ = vulnequalFields
	// vulnequalDescID is the schema descriptor for id field.
	vulnequalDescID := vulnequalFields[0].Descriptor()
	// vulnequal.DefaultID holds the default value on creation for the id field.
	vulnequal.DefaultID = vulnequalDescID.Default.(func() uuid.UUID)
	vulnerabilityidFields := schema.VulnerabilityID{}.Fields()
	_ = vulnerabilityidFields
	// vulnerabilityidDescType is the schema descriptor for type field.
	vulnerabilityidDescType := vulnerabilityidFields[2].Descriptor()
	// vulnerabilityid.TypeValidator is a validator for the "type" field. It is called by the builders before save.
	vulnerabilityid.TypeValidator = vulnerabilityidDescType.Validators[0].(func(string) error)
	// vulnerabilityidDescID is the schema descriptor for id field.
	vulnerabilityidDescID := vulnerabilityidFields[0].Descriptor()
	// vulnerabilityid.DefaultID holds the default value on creation for the id field.
	vulnerabilityid.DefaultID = vulnerabilityidDescID.Default.(func() uuid.UUID)
	vulnerabilitymetadataFields := schema.VulnerabilityMetadata{}.Fields()
	_ = vulnerabilitymetadataFields
	// vulnerabilitymetadataDescID is the schema descriptor for id field.
	vulnerabilitymetadataDescID := vulnerabilitymetadataFields[0].Descriptor()
	// vulnerabilitymetadata.DefaultID holds the default value on creation for the id field.
	vulnerabilitymetadata.DefaultID = vulnerabilitymetadataDescID.Default.(func() uuid.UUID)
}
