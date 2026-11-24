### Security

- **Stackurity refuses to run behind a connection pooler in transaction mode.** The database role and each organisation's scope are set once per database connection, so a pooler that moves connections between PostgreSQL sessions (PgBouncer `pool_mode = transaction`, for example) could run a query with another request's scope, with none, or as the login role, and workspaces would not be isolated. Every command that uses the database now checks this when it starts and refuses with a message that says how to fix it, and `stackurity doctor` has a new `pooler` check. A pooler in session mode, or a direct connection, works as before. See [Connection poolers](docs/operations.md#connection-poolers). ([#539](https://github.com/stackurity/stackurity/issues/539), [#540](https://github.com/stackurity/stackurity/issues/540))

### Upgrading

- If `STACKURITY_DATABASE_URL` points at a pooler in transaction or statement mode, switch it to session mode or connect straight to PostgreSQL before upgrading: the server will not start behind it.
