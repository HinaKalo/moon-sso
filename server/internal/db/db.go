// Package db owns the MySQL connection pool, transactions and migrations.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

type DB struct {
	*sql.DB
	Name string // database (schema) name, used for lock names
}

type Options struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// Open connects to MySQL with settings this application relies on:
// UTC timestamps, parseTime, utf8mb4 and strict SQL mode.
func Open(ctx context.Context, o Options) (*DB, error) {
	cfg, err := mysql.ParseDSN(o.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: parse dsn: %w", err)
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	// READ COMMITTED for every connection: no gap locks on the hot token paths
	// and no per-transaction SET statement.
	cfg.Params["transaction_isolation"] = "'READ-COMMITTED'"
	cfg.Params["sql_mode"] = "'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"
	cfg.Collation = "utf8mb4_0900_ai_ci"
	cfg.InterpolateParams = false
	cfg.MultiStatements = false
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	sqlDB := sql.OpenDB(connector)
	sqlDB.SetMaxOpenConns(o.MaxOpenConns)
	sqlDB.SetMaxIdleConns(o.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(o.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &DB{DB: sqlDB, Name: cfg.DBName}, nil
}

// Querier is implemented by *sql.DB, *sql.Tx and *sql.Conn.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx runs fn in a transaction at the given isolation level. Deadlocks and
// lock wait timeouts are retried a few times since every transaction in this
// code base is safe to replay.
func (d *DB) Tx(ctx context.Context, iso sql.IsolationLevel, fn func(tx *sql.Tx) error) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		err = d.tx(ctx, iso, fn)
		if !isRetryable(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt+1) * 15 * time.Millisecond):
		}
	}
	return err
}

func (d *DB) tx(ctx context.Context, iso sql.IsolationLevel, fn func(tx *sql.Tx) error) (err error) {
	opts := &sql.TxOptions{}
	if iso != sql.LevelReadCommitted && iso != sql.LevelDefault {
		opts.Isolation = iso
	}
	tx, err := d.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func isRetryable(err error) bool {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Number == 1213 || me.Number == 1205 // deadlock, lock wait timeout
	}
	return false
}

// IsDuplicate reports a unique key violation.
func IsDuplicate(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}

// Lock acquires a named MySQL advisory lock on a dedicated connection.
// The returned release function must be called to free the lock and connection.
func (d *DB) Lock(ctx context.Context, name string, wait time.Duration) (release func(), err error) {
	conn, err := d.Conn(ctx)
	if err != nil {
		return nil, err
	}
	full := d.Name + ":" + name
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", full, int(wait.Seconds())).Scan(&got); err != nil {
		conn.Close()
		return nil, err
	}
	if !got.Valid || got.Int64 != 1 {
		conn.Close()
		return nil, ErrLockBusy
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", full)
		conn.Close()
	}, nil
}

var ErrLockBusy = errors.New("db: lock held by another process")

// NullTime converts a nullable time.
func NullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
