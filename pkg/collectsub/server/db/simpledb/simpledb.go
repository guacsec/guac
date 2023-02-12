//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package simpledb

import (
	"context"
	"sync"

	"github.com/gobwas/glob"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	db "github.com/guacsec/guac/pkg/collectsub/server/db/types"
)

func NewSimpleDb() (db.CollectSubscriberDb, error) {
	return &simpleDb{
		lock: &sync.RWMutex{},
	}, nil
}

type simpleDb struct {
	collectEntries []*pb.CollectEntry
	lock           *sync.RWMutex
}

func entryKeyEq(e1, e2 *pb.CollectEntry) bool {
	return e1.GetValue() == e2.GetValue() &&
		e1.GetType() == e2.GetType()
}

func (s *simpleDb) containsEntry(e *pb.CollectEntry) bool {
	for _, ee := range s.collectEntries {
		if entryKeyEq(e, ee) {
			return true
		}
	}
	return false
}

func (s *simpleDb) AddCollectEntries(ctx context.Context, entries []*pb.CollectEntry) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, e := range entries {
		if e != nil && !s.containsEntry(e) {
			s.collectEntries = append(s.collectEntries, e)
		}
	}
	return nil
}

func (s *simpleDb) GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	var filterMatchers []glob.Glob
	for _, f := range filters {
		filterMatchers = append(filterMatchers, glob.MustCompile(f.Glob))
	}

	var retList []*pb.CollectEntry
	for _, e := range s.collectEntries {
		for i, f := range filters {
			matched := filterMatchers[i].Match(e.Value)
			if e.Type == f.Type && matched {
				retList = append(retList, e)
				break
			}
		}
	}

	return retList, nil
}
