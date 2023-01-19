package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type Neo4jCredentials struct {
	User string
	Pass string
	Realm string
	DBAddr string
}

type neo4jClient struct {
	driver neo4j.Driver
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	creds := args.(*Neo4jCredentials)
	token := neo4j.BasicAuth(creds.User, creds.Pass, creds.Realm)
	driver, err := neo4j.NewDriver(creds.DBAddr, token)
	if err != nil {
		return nil, err
	}

	if err = driver.VerifyConnectivity(); err != nil {
		driver.Close()
		return nil, err
	}

	return &neo4jClient{driver}, nil
}

func (c *neo4jClient) Artifacts(ctx context.Context) ([]*model.Artifact, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := "MATCH (n:Artifact) return n.digest, n.name"
			result, err := tx.Run(query, nil)
			if err != nil {
				return nil, err
			}

			var artifacts []*model.Artifact
			for result.Next() {
				artifact := model.Artifact{
					Digest: result.Record().Values[0].(string),
				}
				if result.Record().Values[1] != nil {
					packageName := result.Record().Values[1].(string)
					artifact.Name = &packageName
				}
				artifacts = append(artifacts, &artifact)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return artifacts, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Artifact), nil
}
