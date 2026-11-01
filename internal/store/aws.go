package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/awsconnect"
)

// AWSConnection is one AWS account connected with the Stackurity
// CloudFormation stack (migration 0073).
type AWSConnection struct {
	ID                int64      `json:"id"`
	WorkspaceID       int64      `json:"workspace_id"`
	ExternalID        string     `json:"external_id"`
	Regions           []string   `json:"regions"`
	AgentInstall      bool       `json:"agent_install"`
	Status            string     `json:"status"`
	RoleARN           string     `json:"role_arn"`
	AccountID         string     `json:"account_id"`
	LastError         string     `json:"last_error"`
	IntegrationID     *int64     `json:"integration_id"`
	CallbackExpiresAt *time.Time `json:"callback_expires_at"`
	CallbackUsedAt    *time.Time `json:"callback_used_at"`
	CreatedBy         *int64     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	VerifiedAt        *time.Time `json:"verified_at"`
}

const awsConnCols = `id, workspace_id, external_id, regions, agent_install, status, role_arn, account_id, last_error, integration_id,
	callback_expires_at, callback_used_at, created_by, created_at, verified_at`

func collectAWSConn(rows pgx.Rows, err error) (*AWSConnection, error) {
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[AWSConnection])
	return c, notFound(err)
}

// CreateAWSConnection starts a connection in the caller's workspace with a
// new external ID.
func (s *Store) CreateAWSConnection(ctx context.Context, regions []string, agentInstall bool, createdBy int64) (*AWSConnection, error) {
	ext, err := awsconnect.NewExternalID()
	if err != nil {
		return nil, err
	}
	var by *int64
	if createdBy > 0 {
		by = &createdBy
	}
	return collectAWSConn(s.Pool.Query(ctx, `INSERT INTO aws_connections (external_id, regions, agent_install, created_by)
		VALUES ($1, $2, $3, $4) RETURNING `+awsConnCols, ext, regions, agentInstall, by))
}

// SetAWSCallback replaces the connection's callback nonce: a token made
// before stops working. An active connection takes no callback.
func (s *Store) SetAWSCallback(ctx context.Context, id int64, nonceHash []byte, expires time.Time) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE aws_connections SET callback_nonce_hash = $2, callback_expires_at = $3, callback_used_at = NULL
		WHERE id = $1 AND status <> 'active'`, id, nonceHash, expires)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetAWSOptions changes what a connection that is not active yet asks for.
func (s *Store) SetAWSOptions(ctx context.Context, id int64, agentInstall bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE aws_connections SET agent_install = $2 WHERE id = $1`, id, agentInstall)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListAWSConnections(ctx context.Context) ([]AWSConnection, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+awsConnCols+` FROM aws_connections ORDER BY created_at DESC, id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AWSConnection])
}

func (s *Store) GetAWSConnection(ctx context.Context, id int64) (*AWSConnection, error) {
	return collectAWSConn(s.Pool.Query(ctx, `SELECT `+awsConnCols+` FROM aws_connections WHERE id = $1`, id))
}

// AWSConnectionForIntegration returns the connection an integration was
// created for, or ErrNotFound.
func (s *Store) AWSConnectionForIntegration(ctx context.Context, integrationID int64) (*AWSConnection, error) {
	return collectAWSConn(s.Pool.Query(ctx, `SELECT `+awsConnCols+` FROM aws_connections WHERE integration_id = $1`, integrationID))
}

// DeleteAWSConnection removes a connection and the integration it feeds.
// The role stays in the customer's account until they delete the stack.
func (s *Store) DeleteAWSConnection(ctx context.Context, id int64) (*AWSConnection, error) {
	var c *AWSConnection
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		c, err = collectAWSConn(tx.Query(ctx, `DELETE FROM aws_connections WHERE id = $1 RETURNING `+awsConnCols, id))
		if err != nil {
			return err
		}
		if c.IntegrationID != nil {
			_, err = tx.Exec(ctx, `DELETE FROM integrations WHERE id = $1`, *c.IntegrationID)
		}
		return err
	})
	return c, err
}

// ConsumeAWSCallback takes the role ARN a stack reported, using up the
// token whose signed claims are given. It runs in system scope: the caller
// is the customer's stack, which has no session. Only the connection the
// claims name, in the workspace they name, with their external ID and an
// unused, unexpired nonce, is changed; anything else is ErrNotFound.
func (s *Store) ConsumeAWSCallback(ctx context.Context, c awsconnect.CallbackClaims, roleARN string) (*AWSConnection, error) {
	return collectAWSConn(s.Pool.Query(ctx, `UPDATE aws_connections SET callback_used_at = now(), role_arn = $5, last_error = ''
		WHERE id = $1 AND workspace_id = $2 AND external_id = $3 AND callback_nonce_hash = $4
		  AND callback_used_at IS NULL AND callback_expires_at > now() AND status <> 'active'
		RETURNING `+awsConnCols, c.Connection, c.Workspace, c.ExternalID, awsconnect.NonceHash(c.Nonce), roleARN))
}

// SetAWSRole records a pasted role ARN on a connection that is not active.
func (s *Store) SetAWSRole(ctx context.Context, id int64, roleARN string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE aws_connections SET role_arn = $2 WHERE id = $1 AND status <> 'active'`, id, roleARN)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// FailAWSConnection records why verifying the role failed.
func (s *Store) FailAWSConnection(ctx context.Context, id int64, msg string) error {
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	_, err := s.Pool.Exec(ctx, `UPDATE aws_connections SET status = CASE WHEN status = 'active' THEN 'active' ELSE 'failed' END,
		last_error = $2 WHERE id = $1`, id, msg)
	return err
}

// AWSPluginConfig is the aws-managed plugin integration a connection feeds.
// It never names a role or an external ID: the server assumes the role and
// hands the plugin the session (cmd/stackurity, integration.run).
func AWSPluginConfig(regions []string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"plugin": "aws-managed", "config": map[string]any{"regions": regions}})
	return b
}

// ActivateAWSConnection marks the verified connection active and creates its
// integration (or keeps the one it has). It returns the integration's id.
func (s *Store) ActivateAWSConnection(ctx context.Context, id int64, roleARN string, schedule time.Duration) (int64, error) {
	account := awsconnect.AccountOf(roleARN)
	if account == "" {
		return 0, fmt.Errorf("not an IAM role ARN: %w", ErrInvalid)
	}
	var integ int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		c, err := collectAWSConn(tx.Query(ctx, `SELECT `+awsConnCols+` FROM aws_connections WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if c.RoleARN != roleARN {
			return fmt.Errorf("the role ARN changed while it was being checked: %w", ErrConflict)
		}
		if c.IntegrationID != nil {
			integ = *c.IntegrationID
		} else {
			name := "AWS " + account
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM integrations WHERE kind = 'plugin' AND name = $1)`, name).Scan(&taken); err != nil {
				return err
			}
			if taken {
				name = fmt.Sprintf("AWS %s (connection %d)", account, id)
			}
			if err := tx.QueryRow(ctx, `INSERT INTO integrations (kind, name, config, secret_ref, schedule) VALUES ('plugin', $1, $2, '', $3) RETURNING id`,
				name, AWSPluginConfig(c.Regions), schedule).Scan(&integ); err != nil {
				if isUniqueViolation(err) {
					return ErrConflict
				}
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE aws_connections SET status = 'active', account_id = $2, integration_id = $3, last_error = '',
			verified_at = now(), callback_nonce_hash = NULL WHERE id = $1`, id, account, integ)
		return err
	})
	return integ, err
}

// AWSAgentInstall is one agent install through SSM.
type AWSAgentInstall struct {
	ID           int64      `json:"id"`
	ConnectionID int64      `json:"connection_id"`
	Region       string     `json:"region"`
	InstanceID   string     `json:"instance_id"`
	ComputerName string     `json:"computer_name"`
	EnrollmentID *int64     `json:"enrollment_id"`
	CommandID    string     `json:"command_id"`
	Status       string     `json:"status"`
	Detail       string     `json:"detail"`
	CreatedBy    *int64     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CheckedAt    *time.Time `json:"checked_at"`
}

const awsInstallCols = `id, connection_id, region, instance_id, computer_name, enrollment_id, command_id, status, detail, created_by,
	created_at, updated_at, checked_at`

// CreateAWSInstall records an install about to be sent.
func (s *Store) CreateAWSInstall(ctx context.Context, in AWSAgentInstall) (*AWSAgentInstall, error) {
	rows, err := s.Pool.Query(ctx, `INSERT INTO aws_agent_installs (connection_id, region, instance_id, computer_name, enrollment_id, command_id, status, detail, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+awsInstallCols,
		in.ConnectionID, in.Region, in.InstanceID, truncateStr(in.ComputerName, 255), in.EnrollmentID, in.CommandID, in.Status, truncateStr(in.Detail, 4000), in.CreatedBy)
	if err != nil {
		return nil, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[AWSAgentInstall])
}

// UpdateAWSInstall records what SSM said about an install.
func (s *Store) UpdateAWSInstall(ctx context.Context, id int64, status, detail string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE aws_agent_installs SET status = $2, detail = $3, checked_at = now(),
		updated_at = CASE WHEN status = $2 AND detail = $3 THEN updated_at ELSE now() END WHERE id = $1`, id, status, truncateStr(detail, 4000))
	return err
}

// ListAWSInstalls returns a connection's installs, newest first.
func (s *Store) ListAWSInstalls(ctx context.Context, connection int64) ([]AWSAgentInstall, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+awsInstallCols+` FROM aws_agent_installs WHERE connection_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 500`, connection)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AWSAgentInstall])
}

// ReportingHostnames returns which of the names (lower-cased) are the
// hostname of a host asset in the caller's workspace, mapped to its id. An
// EC2 instance's SSM computer name is often the FQDN ("ip-10-0-0-1.ec2.
// internal") where the agent reports the short name, so both are tried.
func (s *Store) ReportingHostnames(ctx context.Context, names []string) (map[string]int64, error) {
	var want []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		want = append(want, n)
		if short, _, ok := strings.Cut(n, "."); ok && short != "" {
			want = append(want, short)
		}
	}
	out := map[string]int64{}
	if len(want) == 0 {
		return out, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT lower(i.value), a.id FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
		WHERE i.scheme = 'hostname' AND lower(i.value) = ANY($1) AND a.kind = 'host' AND a.merged_into IS NULL`, want)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var id int64
		if err := rows.Scan(&n, &id); err != nil {
			return nil, err
		}
		out[n] = id
	}
	return out, rows.Err()
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ErrAWSInactive: the connection has not been verified.
var ErrAWSInactive = errors.New("this AWS connection is not active yet: verify its role first")
