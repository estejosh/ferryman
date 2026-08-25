# ADR 0009: Encrypted per-agent keystores

Secrets are protected by encryption, not by transport secrecy. The orchestrator
mints a grant: it encrypts a scoped set of secrets to a specific agent's public
key, signs the result, and discards the plaintext — it is only the encrypter,
never a vault. The signed-and-sealed blob replicates over Syncthing to every
machine; only the agent whose key matches can decrypt it. That is what gives one
agent "specific powers" (GitHub to one, database to another) without sharing a
master secret.

Each agent reuses its existing Ed25519 identity. An X25519 encryption key is
derived from the same seed, so one keypair signs work and decrypts grants — no
second key to distribute or trust. Grants are encrypted to the recipient and
signed by the issuer, so a compromised sync peer cannot plant a forged or
replayed keystore. Every grant carries an expiry and is re-minted per task;
revocation is stop-renewing, with key rotation as the emergency brake.

The grant is a scoped envelope — recipient, secret names by reference (never
values), project scope, expiry, issuer, and an Ed25519 signature — carried inside
the signed v2 portable envelope (see `PORTABLE_AUTHENTICATION.md`). Key portability
defaults to one agent per machine: the private key stays where the agent runs and
is never synced; a passphrase-encrypted portable key is future work if an agent
must roam between machines.
