package client

import (
	"context"
	"fmt"
	"log"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	client pb.ColectSubscriberServiceClient
	conn   *grpc.ClientConn
}

func NewClient(addr string) (*Client, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	c := pb.NewColectSubscriberServiceClient(conn)

	return &Client{
		client: c,
		conn:   conn,
	}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) AddCollectEntry(ctx context.Context, entries []*pb.CollectEntry) error {
	res, err := c.client.AddCollectEntry(ctx, &pb.AddCollectEntriesRequest{
		Entries: entries,
	})
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("add collect entry unsuccessful")
	}
	return nil
}

func (c *Client) GetCollectEntries(ctx context.Context, filters []*pb.CollectEntryFilter) ([]*pb.CollectEntry, error) {
	res, err := c.client.GetCollectEntries(ctx, &pb.GetCollectEntriesRequest{
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}

	return res.Entries, nil
}
