# ADR 0005: Versioned adapter contract

Adapters implement a small versioned trait. The core owns lifecycle, policy, and persistence; adapters only advertise capabilities and translate execution. This prevents provider-specific concepts from becoming core schema.
