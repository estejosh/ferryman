# ADR 0003: Storage port

Core orchestration depends on a storage abstraction; SQLite is the initial implementation. SQL schemas use portable concepts and UUID/text identifiers to keep a PostgreSQL path explicit without claiming it is already supported.
