# Backup and recovery

Stop the Bridge before taking a consistent local backup, then copy these configured locations together:

- SQLite database, including `-wal` and `-shm` files if present;
- artifact root;
- project workspace root;
- bridge-memory root.

To restore, place them back at the same configured paths and start the same Bridge version. Verify with `GET /healthz`, then inspect project jobs and recovery memory before allowing workers to lease work.

Database schema migrations are additive in the current preview. Take a backup before upgrading; rollback of a database migration is not automated.
