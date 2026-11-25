package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sum     string
	stmts   []string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: bad version prefix", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, migration{version: v, name: name, sum: hex.EncodeToString(sum[:]), stmts: splitSQL(string(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

// splitSQL splits on semicolons that end a line. Migrations must not contain
// semicolons at line ends inside string literals.
func splitSQL(s string) []string {
	var stmts []string
	var cur strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			stmt := strings.TrimSpace(cur.String())
			stmts = append(stmts, strings.TrimSuffix(stmt, ";"))
			cur.Reset()
		}
	}
	if rest := strings.TrimSpace(cur.String()); rest != "" {
		stmts = append(stmts, rest)
	}
	return stmts
}

func (d *DB) ensureMigrationTable(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INT NOT NULL PRIMARY KEY,
		name VARCHAR(200) NOT NULL,
		checksum CHAR(64) NOT NULL,
		applied_at DATETIME(3) NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`)
	return err
}

func (d *DB) applied(ctx context.Context) (map[int]string, error) {
	rows, err := d.QueryContext(ctx, "SELECT version, checksum FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, err
		}
		m[v] = sum
	}
	return m, rows.Err()
}

// Migrate applies pending migrations under an advisory lock. MySQL DDL is not
// transactional, so each statement uses a short lock_wait_timeout and every
// migration must be idempotent-safe to re-run after a partial failure.
func (d *DB) Migrate(ctx context.Context, log *slog.Logger) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	release, err := d.Lock(ctx, "migrate", 30*time.Second)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer release()
	if err := d.ensureMigrationTable(ctx); err != nil {
		return err
	}
	done, err := d.applied(ctx)
	if err != nil {
		return err
	}
	conn, err := d.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET SESSION lock_wait_timeout = 5"); err != nil {
		return err
	}
	for _, m := range ms {
		if sum, ok := done[m.version]; ok {
			if sum != m.sum {
				return fmt.Errorf("migration %s was modified after being applied", m.name)
			}
			continue
		}
		log.Info("applying migration", "name", m.name)
		for i, stmt := range m.stmts {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration %s statement %d: %w", m.name, i+1, err)
			}
		}
		if _, err := conn.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
			m.version, m.name, m.sum, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

// CheckSchema verifies that every migration known to this binary has been
// applied. Newer migrations applied by a later release are fine (N-1 rule).
func (d *DB) CheckSchema(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	if err := d.ensureMigrationTable(ctx); err != nil {
		return err
	}
	done, err := d.applied(ctx)
	if err != nil {
		return err
	}
	var missing []string
	for _, m := range ms {
		if _, ok := done[m.version]; !ok {
			missing = append(missing, m.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("database schema is behind this binary; run `moon-sso migrate` first (missing %v)", missing)
	}
	return nil
}
