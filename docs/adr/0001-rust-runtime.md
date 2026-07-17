# ADR 0001: Rust-first runtime

Use Rust for the control plane and SDK contracts. It yields a small deployable binary, explicit concurrency/state ownership, and a stable shared type system without imposing a Python runtime. Language-neutral clients consume OpenAPI.
