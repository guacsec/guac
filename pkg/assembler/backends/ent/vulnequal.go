// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
)

// VulnEqual is the model entity for the VulnEqual schema.
type VulnEqual struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// VulnID holds the value of the "vuln_id" field.
	VulnID uuid.UUID `json:"vuln_id,omitempty"`
	// EqualVulnID holds the value of the "equal_vuln_id" field.
	EqualVulnID uuid.UUID `json:"equal_vuln_id,omitempty"`
	// Justification holds the value of the "justification" field.
	Justification string `json:"justification,omitempty"`
	// Origin holds the value of the "origin" field.
	Origin string `json:"origin,omitempty"`
	// Collector holds the value of the "collector" field.
	Collector string `json:"collector,omitempty"`
	// DocumentRef holds the value of the "document_ref" field.
	DocumentRef string `json:"document_ref,omitempty"`
	// An opaque hash of the vulnerability IDs that are equal
	VulnerabilitiesHash string `json:"vulnerabilities_hash,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the VulnEqualQuery when eager-loading is set.
	Edges        VulnEqualEdges `json:"edges"`
	selectValues sql.SelectValues
}

// VulnEqualEdges holds the relations/edges for other nodes in the graph.
type VulnEqualEdges struct {
	// VulnerabilityA holds the value of the vulnerability_a edge.
	VulnerabilityA *VulnerabilityID `json:"vulnerability_a,omitempty"`
	// VulnerabilityB holds the value of the vulnerability_b edge.
	VulnerabilityB *VulnerabilityID `json:"vulnerability_b,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
	// totalCount holds the count of the edges above.
	totalCount [2]map[string]int
}

// VulnerabilityAOrErr returns the VulnerabilityA value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e VulnEqualEdges) VulnerabilityAOrErr() (*VulnerabilityID, error) {
	if e.VulnerabilityA != nil {
		return e.VulnerabilityA, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: vulnerabilityid.Label}
	}
	return nil, &NotLoadedError{edge: "vulnerability_a"}
}

// VulnerabilityBOrErr returns the VulnerabilityB value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e VulnEqualEdges) VulnerabilityBOrErr() (*VulnerabilityID, error) {
	if e.VulnerabilityB != nil {
		return e.VulnerabilityB, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: vulnerabilityid.Label}
	}
	return nil, &NotLoadedError{edge: "vulnerability_b"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*VulnEqual) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case vulnequal.FieldJustification, vulnequal.FieldOrigin, vulnequal.FieldCollector, vulnequal.FieldDocumentRef, vulnequal.FieldVulnerabilitiesHash:
			values[i] = new(sql.NullString)
		case vulnequal.FieldID, vulnequal.FieldVulnID, vulnequal.FieldEqualVulnID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the VulnEqual fields.
func (ve *VulnEqual) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case vulnequal.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ve.ID = *value
			}
		case vulnequal.FieldVulnID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field vuln_id", values[i])
			} else if value != nil {
				ve.VulnID = *value
			}
		case vulnequal.FieldEqualVulnID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field equal_vuln_id", values[i])
			} else if value != nil {
				ve.EqualVulnID = *value
			}
		case vulnequal.FieldJustification:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field justification", values[i])
			} else if value.Valid {
				ve.Justification = value.String
			}
		case vulnequal.FieldOrigin:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field origin", values[i])
			} else if value.Valid {
				ve.Origin = value.String
			}
		case vulnequal.FieldCollector:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field collector", values[i])
			} else if value.Valid {
				ve.Collector = value.String
			}
		case vulnequal.FieldDocumentRef:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field document_ref", values[i])
			} else if value.Valid {
				ve.DocumentRef = value.String
			}
		case vulnequal.FieldVulnerabilitiesHash:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field vulnerabilities_hash", values[i])
			} else if value.Valid {
				ve.VulnerabilitiesHash = value.String
			}
		default:
			ve.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the VulnEqual.
// This includes values selected through modifiers, order, etc.
func (ve *VulnEqual) Value(name string) (ent.Value, error) {
	return ve.selectValues.Get(name)
}

// QueryVulnerabilityA queries the "vulnerability_a" edge of the VulnEqual entity.
func (ve *VulnEqual) QueryVulnerabilityA() *VulnerabilityIDQuery {
	return NewVulnEqualClient(ve.config).QueryVulnerabilityA(ve)
}

// QueryVulnerabilityB queries the "vulnerability_b" edge of the VulnEqual entity.
func (ve *VulnEqual) QueryVulnerabilityB() *VulnerabilityIDQuery {
	return NewVulnEqualClient(ve.config).QueryVulnerabilityB(ve)
}

// Update returns a builder for updating this VulnEqual.
// Note that you need to call VulnEqual.Unwrap() before calling this method if this VulnEqual
// was returned from a transaction, and the transaction was committed or rolled back.
func (ve *VulnEqual) Update() *VulnEqualUpdateOne {
	return NewVulnEqualClient(ve.config).UpdateOne(ve)
}

// Unwrap unwraps the VulnEqual entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ve *VulnEqual) Unwrap() *VulnEqual {
	_tx, ok := ve.config.driver.(*txDriver)
	if !ok {
		panic("ent: VulnEqual is not a transactional entity")
	}
	ve.config.driver = _tx.drv
	return ve
}

// String implements the fmt.Stringer.
func (ve *VulnEqual) String() string {
	var builder strings.Builder
	builder.WriteString("VulnEqual(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ve.ID))
	builder.WriteString("vuln_id=")
	builder.WriteString(fmt.Sprintf("%v", ve.VulnID))
	builder.WriteString(", ")
	builder.WriteString("equal_vuln_id=")
	builder.WriteString(fmt.Sprintf("%v", ve.EqualVulnID))
	builder.WriteString(", ")
	builder.WriteString("justification=")
	builder.WriteString(ve.Justification)
	builder.WriteString(", ")
	builder.WriteString("origin=")
	builder.WriteString(ve.Origin)
	builder.WriteString(", ")
	builder.WriteString("collector=")
	builder.WriteString(ve.Collector)
	builder.WriteString(", ")
	builder.WriteString("document_ref=")
	builder.WriteString(ve.DocumentRef)
	builder.WriteString(", ")
	builder.WriteString("vulnerabilities_hash=")
	builder.WriteString(ve.VulnerabilitiesHash)
	builder.WriteByte(')')
	return builder.String()
}

// VulnEquals is a parsable slice of VulnEqual.
type VulnEquals []*VulnEqual
