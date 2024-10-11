//!
//! # ChainDEV
//!
//! Blockchain cluster management,
//! supports both single-machine multi-process mode
//! and multi-machine distributed mode.
//!

#![deny(warnings)]
// #![warn(missing_docs)]

pub mod common;

#[cfg(feature = "beacon_based")]
pub mod beacon_based;

#[cfg(feature = "tendermint_based")]
pub mod tendermint_based;

/////////////////////////////////////////////////////////////////////

pub use common::*;

#[cfg(feature = "tendermint_based")]
pub use tendermint_based::dev as tendermint_dev;

#[cfg(feature = "tendermint_based")]
pub use tendermint_based::ddev as tendermint_ddev;

#[cfg(feature = "beacon_based")]
pub use beacon_based::dev as beacon_dev;

#[cfg(feature = "beacon_based")]
pub use beacon_based::ddev as beacon_ddev;

#[cfg(feature = "beacon_based")]
pub use beacon_based::ddev::{host, remote};

/////////////////////////////////////////////////////////////////////

#[macro_export]
macro_rules! check_errlist {
    ($errlist: expr) => {{
        if $errlist.is_empty() {
            Ok(())
        } else {
            Err(eg!($errlist
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n")))
        }
    }};
    // useful fo some middle returns
    (@$errlist: expr) => {{
        if !$errlist.is_empty() {
            return Err(eg!($errlist
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n")));
        }
    }};
}

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
