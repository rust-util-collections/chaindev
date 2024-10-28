pub(crate) use crate::common::*;
use nix::unistd;
use ruc::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{env, fmt, fs, sync::LazyLock};

///////////////////////////////////////////////////////////////////////////

pub const NODE_HOME_GENESIS_DST: &str = "genesis.tar.gz";
pub const NODE_HOME_VCDATA_DST: &str = "vcdata.tar.gz";
pub const MGMT_OPS_LOG: &str = "mgmt.log";

///////////////////////////////////////////////////////////////////////////

pub trait CustomData:
    Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>
{
}

/// Allocate ports based on this trait
pub trait NodePorts:
    Clone + Default + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    /// Reserved ports defined both
    /// by the Beacon and the Execution Client
    fn reserved() -> Vec<u16> {
        let mut ret = Self::el_reserved();
        ret.extend_from_slice(&Self::cl_reserved());
        ret
    }

    /// Reserve wide-used ports for the default node
    ///
    /// - lighthouse bn(discovery port): 9000
    /// - lighthouse bn(quic port): 9001
    /// - lighthouse bn(http rpc): 5052
    /// - lighthouse bn(prometheus metrics): 5054
    /// - lighthouse vc(http rpc): 5062
    /// - lighthouse vc(prometheus metrics): 5064
    fn cl_reserved() -> Vec<u16>;

    /// Reserved ports defined by the Execution Client
    ///
    /// - geth/reth(web3 rpc): 8545, 8546
    /// - geth/reth(engine api): 8551
    /// - geth/reth(discovery port): 30303
    /// - reth(discovery v5 port): 9200
    /// - geth(prometheus metrics): 6060
    fn el_reserved() -> Vec<u16>;

    /// Check and return the new created port set
    fn try_create(ports: &[u16]) -> Result<Self>;

    /// Get all actual ports from the instance,
    /// all: <sys ports> + <app ports>
    fn get_port_list(&self) -> Vec<u16>;

    /// The p2p listening port in the execution side,
    /// may be used in generating the enode address for an execution node
    fn get_el_p2p(&self) -> u16; // { 30303 }

    /// The engine API listening port in the execution side
    /// usage(beacon): `--execution-endpoints="http://localhost:8551"`
    fn get_el_engine_api(&self) -> u16; // { 8551 }

    /// The rpc listening port in the app side,
    /// eg. ETH el(geth/reth) web3 http API rpc
    fn get_el_rpc(&self) -> u16; // { 8545 }

    /// The rpc listening port in the app side,
    /// eg. ETH el(geth/reth) web3 websocket API rpc
    fn get_el_rpc_ws(&self) -> u16; // { 8546 }

    /// The p2p(tcp/udp protocol) listening port in the beacon side
    /// may be used in generating the ENR address for a beacon node
    fn get_cl_p2p_bn(&self) -> u16; // { 9000 }

    /// The p2p(quic protocol) listening port in the beacon side
    /// may be used in generating the ENR address for a beacon node
    fn get_cl_p2p_bn_quic(&self) -> u16; // { 9001 }

    /// The rpc listening port in the beacon side,
    /// usage(beacon): `--checkpoint-sync-url="http://${peer_ip}:5052"`
    fn get_cl_rpc_bn(&self) -> u16; // { 5052 }

    /// The rpc listening port in the vc side
    fn get_cl_rpc_vc(&self) -> u16; // { 5062 }
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

// global shared paths should not be used to avoid confusion
// when multiple users share a same physical machine
pub static BASE_DIR: LazyLock<String> = LazyLock::new(|| {
    let ret = env::var("RUNTIME_CHAIN_DEV_BASE_DIR").unwrap_or_else(|_| {
        format!(
            "/tmp/__CHAIN_DEV__/beacon_based/{}/{}+{}",
            option_env!("STATIC_CHAIN_DEV_BASE_DIR_SUFFIX").unwrap_or(""),
            unistd::gethostname().unwrap().into_string().unwrap(),
            unistd::User::from_uid(unistd::getuid())
                .unwrap()
                .unwrap()
                .name,
        )
    });
    pnk!(fs::create_dir_all(&ret));
    ret
});

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

// pub(crate) const PRESET_DEPOSIT: u128 = 32 * 10_u128.pow(18); // 32 ETH

pub type NodeCustomData = JsonValue;

pub type BlockItv = u16;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum NodeKind {
    Fuhrer,
    ArchiveNode,
    FullNode,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Fuhrer => "fuhrer_node",
            Self::ArchiveNode => "archive_node",
            Self::FullNode => "fullnode",
        };
        write!(f, "{}", msg)
    }
}

// Parse the contents of 'genesis.json'
pub(crate) fn get_pre_mined_accounts_from_genesis_json(
    el_genesis_path: &str,
) -> Result<serde_json::Value> {
    fs::read(el_genesis_path)
        .c(d!())
        .and_then(|g| serde_json::from_slice::<JsonValue>(&g).c(d!()))
        .map(|g| {
            g.as_object()
                .unwrap()
                .get("alloc")
                .unwrap()
                .as_object()
                .unwrap()
                .iter()
                .filter(|account| {
                    account
                        .1
                        .as_object()
                        .unwrap()
                        .get("balance")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap()
                        > 10_u128.pow(17)
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<JsonValue>()
        })
}
