// Code generated by ent, DO NOT EDIT.

package pointofcontact

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the pointofcontact type in the database.
	Label = "point_of_contact"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldSourceID holds the string denoting the source_id field in the database.
	FieldSourceID = "source_id"
	// FieldPackageVersionID holds the string denoting the package_version_id field in the database.
	FieldPackageVersionID = "package_version_id"
	// FieldPackageNameID holds the string denoting the package_name_id field in the database.
	FieldPackageNameID = "package_name_id"
	// FieldArtifactID holds the string denoting the artifact_id field in the database.
	FieldArtifactID = "artifact_id"
	// FieldEmail holds the string denoting the email field in the database.
	FieldEmail = "email"
	// FieldInfo holds the string denoting the info field in the database.
	FieldInfo = "info"
	// FieldSince holds the string denoting the since field in the database.
	FieldSince = "since"
	// FieldJustification holds the string denoting the justification field in the database.
	FieldJustification = "justification"
	// FieldOrigin holds the string denoting the origin field in the database.
	FieldOrigin = "origin"
	// FieldCollector holds the string denoting the collector field in the database.
	FieldCollector = "collector"
	// EdgeSource holds the string denoting the source edge name in mutations.
	EdgeSource = "source"
	// EdgePackageVersion holds the string denoting the package_version edge name in mutations.
	EdgePackageVersion = "package_version"
	// EdgeAllVersions holds the string denoting the all_versions edge name in mutations.
	EdgeAllVersions = "all_versions"
	// EdgeArtifact holds the string denoting the artifact edge name in mutations.
	EdgeArtifact = "artifact"
	// Table holds the table name of the pointofcontact in the database.
	Table = "point_of_contacts"
	// SourceTable is the table that holds the source relation/edge.
	SourceTable = "point_of_contacts"
	// SourceInverseTable is the table name for the SourceName entity.
	// It exists in this package in order to avoid circular dependency with the "sourcename" package.
	SourceInverseTable = "source_names"
	// SourceColumn is the table column denoting the source relation/edge.
	SourceColumn = "source_id"
	// PackageVersionTable is the table that holds the package_version relation/edge.
	PackageVersionTable = "point_of_contacts"
	// PackageVersionInverseTable is the table name for the PackageVersion entity.
	// It exists in this package in order to avoid circular dependency with the "packageversion" package.
	PackageVersionInverseTable = "package_versions"
	// PackageVersionColumn is the table column denoting the package_version relation/edge.
	PackageVersionColumn = "package_version_id"
	// AllVersionsTable is the table that holds the all_versions relation/edge.
	AllVersionsTable = "point_of_contacts"
	// AllVersionsInverseTable is the table name for the PackageName entity.
	// It exists in this package in order to avoid circular dependency with the "packagename" package.
	AllVersionsInverseTable = "package_names"
	// AllVersionsColumn is the table column denoting the all_versions relation/edge.
	AllVersionsColumn = "package_name_id"
	// ArtifactTable is the table that holds the artifact relation/edge.
	ArtifactTable = "point_of_contacts"
	// ArtifactInverseTable is the table name for the Artifact entity.
	// It exists in this package in order to avoid circular dependency with the "artifact" package.
	ArtifactInverseTable = "artifacts"
	// ArtifactColumn is the table column denoting the artifact relation/edge.
	ArtifactColumn = "artifact_id"
)

// Columns holds all SQL columns for pointofcontact fields.
var Columns = []string{
	FieldID,
	FieldSourceID,
	FieldPackageVersionID,
	FieldPackageNameID,
	FieldArtifactID,
	FieldEmail,
	FieldInfo,
	FieldSince,
	FieldJustification,
	FieldOrigin,
	FieldCollector,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

// OrderOption defines the ordering options for the PointOfContact queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// BySourceID orders the results by the source_id field.
func BySourceID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSourceID, opts...).ToFunc()
}

// ByPackageVersionID orders the results by the package_version_id field.
func ByPackageVersionID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPackageVersionID, opts...).ToFunc()
}

// ByPackageNameID orders the results by the package_name_id field.
func ByPackageNameID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPackageNameID, opts...).ToFunc()
}

// ByArtifactID orders the results by the artifact_id field.
func ByArtifactID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldArtifactID, opts...).ToFunc()
}

// ByEmail orders the results by the email field.
func ByEmail(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEmail, opts...).ToFunc()
}

// ByInfo orders the results by the info field.
func ByInfo(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldInfo, opts...).ToFunc()
}

// BySince orders the results by the since field.
func BySince(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSince, opts...).ToFunc()
}

// ByJustification orders the results by the justification field.
func ByJustification(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldJustification, opts...).ToFunc()
}

// ByOrigin orders the results by the origin field.
func ByOrigin(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldOrigin, opts...).ToFunc()
}

// ByCollector orders the results by the collector field.
func ByCollector(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCollector, opts...).ToFunc()
}

// BySourceField orders the results by source field.
func BySourceField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSourceStep(), sql.OrderByField(field, opts...))
	}
}

// ByPackageVersionField orders the results by package_version field.
func ByPackageVersionField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newPackageVersionStep(), sql.OrderByField(field, opts...))
	}
}

// ByAllVersionsField orders the results by all_versions field.
func ByAllVersionsField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newAllVersionsStep(), sql.OrderByField(field, opts...))
	}
}

// ByArtifactField orders the results by artifact field.
func ByArtifactField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newArtifactStep(), sql.OrderByField(field, opts...))
	}
}
func newSourceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SourceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, SourceTable, SourceColumn),
	)
}
func newPackageVersionStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(PackageVersionInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, PackageVersionTable, PackageVersionColumn),
	)
}
func newAllVersionsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(AllVersionsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, AllVersionsTable, AllVersionsColumn),
	)
}
func newArtifactStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ArtifactInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, ArtifactTable, ArtifactColumn),
	)
}
