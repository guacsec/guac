package ent

import (
	"context"
	"database/sql"
)

func WithinTX[T any](ctx context.Context, entClient *Client, next func(context.Context) (*T, error)) (*T, error) {
	tx, err := entClient.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return nil, err
	}
	ctx = NewTxContext(ctx, tx)
	ctx = NewContext(ctx, tx.Client())

	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()

	result, err := next(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return result, nil
}
