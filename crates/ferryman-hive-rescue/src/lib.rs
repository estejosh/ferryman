//! The Hive rescue channel (ADR 0027): a way for a machine that is cut off from the relay
//! and every peer to learn where the master is, without the lane, a relay, a server of ours
//! or Syncthing.
//!
//! - There is no routine posting. When the master has been cut off for 15 minutes it posts
//!   ONE `custom_json` operation under the fleet's Hive account: a record signed by the
//!   master and sealed so only roster members can read it (see [`record`]). It also posts
//!   when its relay or the fleet relay list changes.
//! - Every other machine only READS Hive, and only while it is cut off ([`rescuer`]). A
//!   record that verifies feeds iroh a dial address (an address-lookup source) and the
//!   relay it names. It grants nothing: the ordinary roster and grant checks decide access.
//! - Keys: the fleet account's keys are never on a machine. A poster signs with its own
//!   posting key, with the fleet account's posting authority delegated to its account
//!   ([`tx`], [`config`]).
//!
//! Optional: the CLI links this crate only with `--features hive-rescue`, and nothing runs
//! unless `[hive_rescue] enabled = true`.

pub mod config;
pub mod mock;
pub mod record;
pub mod rescuer;
pub mod rpc;
pub mod state;
pub mod tx;

pub use config::{Credentials, RescueConfig};
pub use record::{Kind, Signed};
pub use rescuer::{FleetView, LaneInfo, Rescuer, TickReport, cut_off_since, view_from_root};
