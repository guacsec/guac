package testutils

import (
	"context"
	"database/sql"
	"log"

	"github.com/DATA-DOG/go-txdb"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/enttest"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/suite"

	dsql "entgo.io/ent/dialect/sql"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

func init() {
	txdb.Register("txdb", "postgres", "guac_test")
}

type Suite struct {
	suite.Suite
	Ctx         context.Context
	Client      *ent.Client
	db          *sql.DB
	beforeHooks []func(suiteName, testName string)
	afterHooks  []func()
}

func TestSuite() *Suite {
	return &Suite{}
}

func (s *Suite) Run(testName string, tf func()) {
	_, err := s.db.Exec("SAVEPOINT savepoint1")
	if err != nil {
		log.Fatal(err)
	}
	defer s.db.Exec("ROLLBACK TO SAVEPOINT savepoint1")
	s.Suite.Run(testName, tf)
}

func (s *Suite) BeforeEach(fn func(suiteName, testName string)) {
	s.beforeHooks = append(s.beforeHooks, fn)
}

func (s *Suite) AfterEach(fn func()) {
	s.afterHooks = append(s.afterHooks, fn)
}

func (s *Suite) BeforeTest(suiteName, testName string) {
	ctx := context.Background()
	ident := ksuid.New().String()
	db, err := sql.Open("txdb", ident)
	if err != nil {
		log.Fatal(err)
	}
	s.db = db
	entSqlDriver := dsql.OpenDB("postgres", db)
	// enttest automatically runs migrations to create the schema in the test database.
	client := enttest.NewClient(s.T(), enttest.WithOptions(ent.Driver(entSqlDriver)))
	log.Println("BeforeTest hook", suiteName, testName)
	s.Client = client

	// Populate context with ent client so that transactions work
	ctx = ent.NewContext(ctx, s.Client)
	s.Ctx = ctx

	for _, fn := range s.beforeHooks {
		fn(suiteName, testName)
	}
}

func (s *Suite) AfterTest(suiteName, testName string) {
	s.Client.Close()
}

var _ suite.BeforeTest = (*Suite)(nil)
var _ suite.AfterTest = (*Suite)(nil)
