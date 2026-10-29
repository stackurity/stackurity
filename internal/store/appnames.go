package store

import (
	"context"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// Applications are named "<app> on <host>" by the agent. Two copies of one
// application on a host (phpMyAdmin in /var/www/html/phpmyadmin and in
// /var/www/html/demo/phpmyadmin) would get the same name, so a new one that
// would clash gets its path, relative to the directory the copies share:
// "phpmyadmin (/phpmyadmin) on DBC" and "phpmyadmin (/demo/phpmyadmin) on
// DBC". An earlier copy still carrying exactly the generated name is
// renamed the same way; a name a person set is never changed. The same
// runs for an existing copy each time it reports, so copies named alike
// before this existed are told apart too (migration 0050 renamed those
// already in the database).

// appName returns the name for the batch's application: the batch's name,
// with the application's path added when another copy on the host has the
// same one. It renames clashing copies in the same transaction. self is
// the asset when it exists already (0 for a new one); its own row is
// renamed here only while it carries the plain generated name.
func appName(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch, self int64) (string, error) {
	name := b.Asset.Name
	if b.Asset.Kind != model.AssetApplication || len(b.Asset.Identifiers) != 1 || b.Asset.Identifiers[0].Scheme != model.AppPathScheme {
		return name, nil
	}
	hostName := b.Asset.Attributes["host"]
	suffix := " on " + hostName
	value := b.Asset.Identifiers[0].Value // host:<id>:<path>, set by the API
	if hostName == "" || !strings.HasSuffix(name, suffix) || !strings.HasPrefix(value, "host:") {
		return name, nil
	}
	rest := strings.TrimPrefix(value, "host:")
	hostID, dir, ok := strings.Cut(rest, ":")
	if !ok || !strings.HasPrefix(dir, "/") {
		return name, nil
	}
	app := strings.TrimSuffix(name, suffix)
	// One naming at a time per host, so two copies reporting at once
	// cannot both take the plain name.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('app-names:' || $1))`, hostID); err != nil {
		return "", err
	}
	prefix := "host:" + hostID + ":"
	rows, err := tx.Query(ctx, `SELECT a.id, a.name, a.name_by_person, ai.value FROM asset_identifiers ai
		JOIN assets a ON a.id = ai.asset_id
		WHERE ai.scheme = $1 AND left(ai.value, length($2)) = $2 AND a.merged_into IS NULL AND a.kind = 'application'`,
		model.AppPathScheme, prefix)
	if err != nil {
		return "", err
	}
	type sibling struct {
		id     int64
		name   string
		person bool
		dir    string
	}
	var same []sibling
	for rows.Next() {
		var s sibling
		var v string
		if err := rows.Scan(&s.id, &s.name, &s.person, &v); err != nil {
			rows.Close()
			return "", err
		}
		if s.id == self {
			continue
		}
		s.dir = strings.TrimPrefix(v, prefix)
		// Copies of the same application: the plain generated name, or one
		// with a path already added.
		if s.name == name || (strings.HasPrefix(s.name, app+" (") && strings.HasSuffix(s.name, ")"+suffix)) {
			same = append(same, s)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(same) == 0 {
		return name, nil
	}
	dirs := []string{dir}
	for _, s := range same {
		dirs = append(dirs, s.dir)
	}
	label := appPaths(dirs)
	for _, s := range same {
		if s.person || s.name != name {
			continue // a person's name, or one already told apart
		}
		if _, err := tx.Exec(ctx, `UPDATE assets SET name = $2 WHERE id = $1 AND NOT name_by_person`,
			s.id, app+" ("+label[path.Clean(s.dir)]+")"+suffix); err != nil {
			return "", err
		}
	}
	named := app + " (" + label[path.Clean(dir)] + ")" + suffix
	if self != 0 {
		if _, err := tx.Exec(ctx, `UPDATE assets SET name = $3 WHERE id = $1 AND name = $2 AND NOT name_by_person`, self, name, named); err != nil {
			return "", err
		}
	}
	return named, nil
}

// appPaths labels each directory by its path below the directory they all
// share ("/var/www/html/phpmyadmin" and "/var/www/html/demo/phpmyadmin"
// become "/phpmyadmin" and "/demo/phpmyadmin"); with nothing shared but
// the root, the full path.
func appPaths(dirs []string) map[string]string {
	common := ""
	for i, d := range dirs {
		parent := path.Dir(path.Clean(d))
		if i == 0 {
			common = parent
			continue
		}
		for common != "/" && parent != common && !strings.HasPrefix(parent, common+"/") {
			common = path.Dir(common)
		}
	}
	out := map[string]string{}
	for _, d := range dirs {
		d = path.Clean(d)
		if common == "/" || common == "" {
			out[d] = d
		} else {
			out[d] = strings.TrimPrefix(d, common)
		}
	}
	return out
}
