package simpledb

import (
	"context"
	"path/filepath"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/server/db"
)

func NewSimpleDb() (db.CollectSubscriberDb, error) {
	return &simpleDb{}, nil
}

type simpleDb struct {
	collectEntries []pb.CollectEntry
}

func (s *simpleDb) AddCollectEntries(ctx context.Context, entries []*pb.CollectEntry) error {
	for _, e := range entries {
		s.collectEntries = append(s.collectEntries, *e)
	}
	return nil
}

func (s *simpleDb) GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error) {
	var retList []*pb.CollectEntry
	for _, e := range s.collectEntries {
		for _, f := range filters {
			matched, err := filepath.Match(f.Glob, e.Value)
			globCheck := err == nil && matched
			if e.Type == f.Type && globCheck {
				retList = append(retList, &e)
				break
			}
		}
	}

	return retList, nil
}
