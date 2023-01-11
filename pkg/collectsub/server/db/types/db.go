package types

import (
	"context"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
)

type CollectSubscriberDb interface {
	AddCollectEntries(context.Context, []*pb.CollectEntry) error
	GetCollectEntries(context.Context, []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error)
}
