// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/schema"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/scorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	certificationFields := schema.Certification{}.Fields()
	_ = certificationFields
	packagenameFields := schema.PackageName{}.Fields()
	_ = packagenameFields
	// packagenameDescName is the schema descriptor for name field.
	packagenameDescName := packagenameFields[1].Descriptor()
	// packagename.NameValidator is a validator for the "name" field. It is called by the builders before save.
	packagename.NameValidator = packagenameDescName.Validators[0].(func(string) error)
	packagetypeFields := schema.PackageType{}.Fields()
	_ = packagetypeFields
	// packagetypeDescType is the schema descriptor for type field.
	packagetypeDescType := packagetypeFields[0].Descriptor()
	// packagetype.TypeValidator is a validator for the "type" field. It is called by the builders before save.
	packagetype.TypeValidator = packagetypeDescType.Validators[0].(func(string) error)
	packageversionFields := schema.PackageVersion{}.Fields()
	_ = packageversionFields
	// packageversionDescVersion is the schema descriptor for version field.
	packageversionDescVersion := packageversionFields[1].Descriptor()
	// packageversion.DefaultVersion holds the default value on creation for the version field.
	packageversion.DefaultVersion = packageversionDescVersion.Default.(string)
	// packageversionDescSubpath is the schema descriptor for subpath field.
	packageversionDescSubpath := packageversionFields[2].Descriptor()
	// packageversion.DefaultSubpath holds the default value on creation for the subpath field.
	packageversion.DefaultSubpath = packageversionDescSubpath.Default.(string)
	scorecardFields := schema.Scorecard{}.Fields()
	_ = scorecardFields
	// scorecardDescAggregateScore is the schema descriptor for aggregate_score field.
	scorecardDescAggregateScore := scorecardFields[1].Descriptor()
	// scorecard.DefaultAggregateScore holds the default value on creation for the aggregate_score field.
	scorecard.DefaultAggregateScore = scorecardDescAggregateScore.Default.(float64)
	// scorecardDescTimeScanned is the schema descriptor for time_scanned field.
	scorecardDescTimeScanned := scorecardFields[2].Descriptor()
	// scorecard.DefaultTimeScanned holds the default value on creation for the time_scanned field.
	scorecard.DefaultTimeScanned = scorecardDescTimeScanned.Default.(func() time.Time)
	vulnerabilitytypeFields := schema.VulnerabilityType{}.Fields()
	_ = vulnerabilitytypeFields
	// vulnerabilitytypeDescType is the schema descriptor for type field.
	vulnerabilitytypeDescType := vulnerabilitytypeFields[0].Descriptor()
	// vulnerabilitytype.TypeValidator is a validator for the "type" field. It is called by the builders before save.
	vulnerabilitytype.TypeValidator = vulnerabilitytypeDescType.Validators[0].(func(string) error)
}
