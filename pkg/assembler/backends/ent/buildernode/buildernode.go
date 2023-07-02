// Code generated by ent, DO NOT EDIT.

package buildernode

import (
	"entgo.io/ent/dialect/sql"
)

const (
	// Label holds the string label denoting the buildernode type in the database.
	Label = "builder_node"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldURI holds the string denoting the uri field in the database.
	FieldURI = "uri"
	// Table holds the table name of the buildernode in the database.
	Table = "builder_nodes"
)

// Columns holds all SQL columns for buildernode fields.
var Columns = []string{
	FieldID,
	FieldURI,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "builder_nodes"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"slsa_attestation_built_by",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

// OrderOption defines the ordering options for the BuilderNode queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByURI orders the results by the uri field.
func ByURI(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldURI, opts...).ToFunc()
}
