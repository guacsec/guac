// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// CertifyScorecard is the model entity for the CertifyScorecard schema.
type CertifyScorecard struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// SourceID holds the value of the "source_id" field.
	SourceID uuid.UUID `json:"source_id,omitempty"`
	// Checks holds the value of the "checks" field.
	Checks []*model.ScorecardCheck `json:"checks,omitempty"`
	// Overall Scorecard score for the source
	AggregateScore float64 `json:"aggregate_score,omitempty"`
	// TimeScanned holds the value of the "time_scanned" field.
	TimeScanned time.Time `json:"time_scanned,omitempty"`
	// ScorecardVersion holds the value of the "scorecard_version" field.
	ScorecardVersion string `json:"scorecard_version,omitempty"`
	// ScorecardCommit holds the value of the "scorecard_commit" field.
	ScorecardCommit string `json:"scorecard_commit,omitempty"`
	// Origin holds the value of the "origin" field.
	Origin string `json:"origin,omitempty"`
	// Collector holds the value of the "collector" field.
	Collector string `json:"collector,omitempty"`
	// DocumentRef holds the value of the "document_ref" field.
	DocumentRef string `json:"document_ref,omitempty"`
	// A SHA1 of the checks fields after sorting keys, used to ensure uniqueness of scorecard records.
	ChecksHash string `json:"checks_hash,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the CertifyScorecardQuery when eager-loading is set.
	Edges        CertifyScorecardEdges `json:"edges"`
	selectValues sql.SelectValues
}

// CertifyScorecardEdges holds the relations/edges for other nodes in the graph.
type CertifyScorecardEdges struct {
	// Source holds the value of the source edge.
	Source *SourceName `json:"source,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
	// totalCount holds the count of the edges above.
	totalCount [1]map[string]int
}

// SourceOrErr returns the Source value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e CertifyScorecardEdges) SourceOrErr() (*SourceName, error) {
	if e.loadedTypes[0] {
		if e.Source == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: sourcename.Label}
		}
		return e.Source, nil
	}
	return nil, &NotLoadedError{edge: "source"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*CertifyScorecard) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case certifyscorecard.FieldChecks:
			values[i] = new([]byte)
		case certifyscorecard.FieldAggregateScore:
			values[i] = new(sql.NullFloat64)
		case certifyscorecard.FieldScorecardVersion, certifyscorecard.FieldScorecardCommit, certifyscorecard.FieldOrigin, certifyscorecard.FieldCollector, certifyscorecard.FieldDocumentRef, certifyscorecard.FieldChecksHash:
			values[i] = new(sql.NullString)
		case certifyscorecard.FieldTimeScanned:
			values[i] = new(sql.NullTime)
		case certifyscorecard.FieldID, certifyscorecard.FieldSourceID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the CertifyScorecard fields.
func (cs *CertifyScorecard) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case certifyscorecard.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				cs.ID = *value
			}
		case certifyscorecard.FieldSourceID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field source_id", values[i])
			} else if value != nil {
				cs.SourceID = *value
			}
		case certifyscorecard.FieldChecks:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field checks", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &cs.Checks); err != nil {
					return fmt.Errorf("unmarshal field checks: %w", err)
				}
			}
		case certifyscorecard.FieldAggregateScore:
			if value, ok := values[i].(*sql.NullFloat64); !ok {
				return fmt.Errorf("unexpected type %T for field aggregate_score", values[i])
			} else if value.Valid {
				cs.AggregateScore = value.Float64
			}
		case certifyscorecard.FieldTimeScanned:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field time_scanned", values[i])
			} else if value.Valid {
				cs.TimeScanned = value.Time
			}
		case certifyscorecard.FieldScorecardVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scorecard_version", values[i])
			} else if value.Valid {
				cs.ScorecardVersion = value.String
			}
		case certifyscorecard.FieldScorecardCommit:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scorecard_commit", values[i])
			} else if value.Valid {
				cs.ScorecardCommit = value.String
			}
		case certifyscorecard.FieldOrigin:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field origin", values[i])
			} else if value.Valid {
				cs.Origin = value.String
			}
		case certifyscorecard.FieldCollector:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field collector", values[i])
			} else if value.Valid {
				cs.Collector = value.String
			}
		case certifyscorecard.FieldDocumentRef:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field document_ref", values[i])
			} else if value.Valid {
				cs.DocumentRef = value.String
			}
		case certifyscorecard.FieldChecksHash:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field checks_hash", values[i])
			} else if value.Valid {
				cs.ChecksHash = value.String
			}
		default:
			cs.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the CertifyScorecard.
// This includes values selected through modifiers, order, etc.
func (cs *CertifyScorecard) Value(name string) (ent.Value, error) {
	return cs.selectValues.Get(name)
}

// QuerySource queries the "source" edge of the CertifyScorecard entity.
func (cs *CertifyScorecard) QuerySource() *SourceNameQuery {
	return NewCertifyScorecardClient(cs.config).QuerySource(cs)
}

// Update returns a builder for updating this CertifyScorecard.
// Note that you need to call CertifyScorecard.Unwrap() before calling this method if this CertifyScorecard
// was returned from a transaction, and the transaction was committed or rolled back.
func (cs *CertifyScorecard) Update() *CertifyScorecardUpdateOne {
	return NewCertifyScorecardClient(cs.config).UpdateOne(cs)
}

// Unwrap unwraps the CertifyScorecard entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (cs *CertifyScorecard) Unwrap() *CertifyScorecard {
	_tx, ok := cs.config.driver.(*txDriver)
	if !ok {
		panic("ent: CertifyScorecard is not a transactional entity")
	}
	cs.config.driver = _tx.drv
	return cs
}

// String implements the fmt.Stringer.
func (cs *CertifyScorecard) String() string {
	var builder strings.Builder
	builder.WriteString("CertifyScorecard(")
	builder.WriteString(fmt.Sprintf("id=%v, ", cs.ID))
	builder.WriteString("source_id=")
	builder.WriteString(fmt.Sprintf("%v", cs.SourceID))
	builder.WriteString(", ")
	builder.WriteString("checks=")
	builder.WriteString(fmt.Sprintf("%v", cs.Checks))
	builder.WriteString(", ")
	builder.WriteString("aggregate_score=")
	builder.WriteString(fmt.Sprintf("%v", cs.AggregateScore))
	builder.WriteString(", ")
	builder.WriteString("time_scanned=")
	builder.WriteString(cs.TimeScanned.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("scorecard_version=")
	builder.WriteString(cs.ScorecardVersion)
	builder.WriteString(", ")
	builder.WriteString("scorecard_commit=")
	builder.WriteString(cs.ScorecardCommit)
	builder.WriteString(", ")
	builder.WriteString("origin=")
	builder.WriteString(cs.Origin)
	builder.WriteString(", ")
	builder.WriteString("collector=")
	builder.WriteString(cs.Collector)
	builder.WriteString(", ")
	builder.WriteString("document_ref=")
	builder.WriteString(cs.DocumentRef)
	builder.WriteString(", ")
	builder.WriteString("checks_hash=")
	builder.WriteString(cs.ChecksHash)
	builder.WriteByte(')')
	return builder.String()
}

// CertifyScorecards is a parsable slice of CertifyScorecard.
type CertifyScorecards []*CertifyScorecard
