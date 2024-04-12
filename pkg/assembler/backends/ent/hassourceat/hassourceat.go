// Code generated by ent, DO NOT EDIT.

package hassourceat

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the hassourceat type in the database.
	Label = "has_source_at"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldPackageVersionID holds the string denoting the package_version_id field in the database.
	FieldPackageVersionID = "package_version_id"
	// FieldPackageNameID holds the string denoting the package_name_id field in the database.
	FieldPackageNameID = "package_name_id"
	// FieldSourceID holds the string denoting the source_id field in the database.
	FieldSourceID = "source_id"
	// FieldKnownSince holds the string denoting the known_since field in the database.
	FieldKnownSince = "known_since"
	// FieldJustification holds the string denoting the justification field in the database.
	FieldJustification = "justification"
	// FieldOrigin holds the string denoting the origin field in the database.
	FieldOrigin = "origin"
	// FieldCollector holds the string denoting the collector field in the database.
	FieldCollector = "collector"
	// FieldDocumentRef holds the string denoting the document_ref field in the database.
	FieldDocumentRef = "document_ref"
	// EdgePackageVersion holds the string denoting the package_version edge name in mutations.
	EdgePackageVersion = "package_version"
	// EdgeAllVersions holds the string denoting the all_versions edge name in mutations.
	EdgeAllVersions = "all_versions"
	// EdgeSource holds the string denoting the source edge name in mutations.
	EdgeSource = "source"
	// Table holds the table name of the hassourceat in the database.
	Table = "has_source_ats"
	// PackageVersionTable is the table that holds the package_version relation/edge.
	PackageVersionTable = "has_source_ats"
	// PackageVersionInverseTable is the table name for the PackageVersion entity.
	// It exists in this package in order to avoid circular dependency with the "packageversion" package.
	PackageVersionInverseTable = "package_versions"
	// PackageVersionColumn is the table column denoting the package_version relation/edge.
	PackageVersionColumn = "package_version_id"
	// AllVersionsTable is the table that holds the all_versions relation/edge.
	AllVersionsTable = "has_source_ats"
	// AllVersionsInverseTable is the table name for the PackageName entity.
	// It exists in this package in order to avoid circular dependency with the "packagename" package.
	AllVersionsInverseTable = "package_names"
	// AllVersionsColumn is the table column denoting the all_versions relation/edge.
	AllVersionsColumn = "package_name_id"
	// SourceTable is the table that holds the source relation/edge.
	SourceTable = "has_source_ats"
	// SourceInverseTable is the table name for the SourceName entity.
	// It exists in this package in order to avoid circular dependency with the "sourcename" package.
	SourceInverseTable = "source_names"
	// SourceColumn is the table column denoting the source relation/edge.
	SourceColumn = "source_id"
)

// Columns holds all SQL columns for hassourceat fields.
var Columns = []string{
	FieldID,
	FieldPackageVersionID,
	FieldPackageNameID,
	FieldSourceID,
	FieldKnownSince,
	FieldJustification,
	FieldOrigin,
	FieldCollector,
	FieldDocumentRef,
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

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// OrderOption defines the ordering options for the HasSourceAt queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByPackageVersionID orders the results by the package_version_id field.
func ByPackageVersionID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPackageVersionID, opts...).ToFunc()
}

// ByPackageNameID orders the results by the package_name_id field.
func ByPackageNameID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPackageNameID, opts...).ToFunc()
}

// BySourceID orders the results by the source_id field.
func BySourceID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSourceID, opts...).ToFunc()
}

// ByKnownSince orders the results by the known_since field.
func ByKnownSince(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldKnownSince, opts...).ToFunc()
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

// ByDocumentRef orders the results by the document_ref field.
func ByDocumentRef(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDocumentRef, opts...).ToFunc()
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

// BySourceField orders the results by source field.
func BySourceField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSourceStep(), sql.OrderByField(field, opts...))
	}
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
func newSourceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SourceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, SourceTable, SourceColumn),
	)
}
