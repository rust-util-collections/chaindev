pub(crate) use crate::common::*;
use nix::unistd;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{env, fmt, fs, sync::LazyLock};

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

/// Allocate ports based on this trait
pub trait NodePorts:
    Clone + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    /// Reserved ports defined both
    /// by the Beacon and the Execution Client
    fn reserved() -> Vec<u16> {
        let mut ret = Self::app_reserved();
        ret.extend_from_slice(&Self::sys_reserved());
        ret
    }

    /// Reserve wide-used ports for the default node
    fn sys_reserved() -> [u16; 12] {
        // - geth/reth(web3 rpc): 8545, 8546
        // - geth/reth(engine api): 8551
        // - geth/reth(discovery port): 30303
        // - reth(discovery v5 port): 9200
        // - geth(prometheus metrics): 6060
        // - lighthouse bn(discovery port): 9000
        // - lighthouse bn(quic port): 9001
        // - lighthouse bn(http rpc): 5052
        // - lighthouse bn(prometheus metrics): 5054
        // - lighthouse vc(http rpc): 5062
        // - lighthouse vc(prometheus metrics): 5064
        [
            8545, 8546, 8551, 30303, 9200, 6060, 9000, 9001, 5052, 5054, 5062, 5064,
        ]
    }

    /// Reserved ports defined by the Execution Client
    fn app_reserved() -> Vec<u16>;

    /// Check and return the new created port set
    fn try_create(ports: &[u16]) -> Result<Self>;

    /// Get all actual ports from the instance,
    /// all: <sys ports> + <app ports>
    fn get_port_list(&self) -> Vec<u16>;

    /// The rpc listening port in the app side,
    /// eg. ETH el(geth/reth) web3 API rpc
    fn get_app_rpc(&self) -> u16; // { 8545 }

    /// The p2p listening port in the execution side,
    /// may be used in generating the enode address for an execution node
    fn get_sys_p2p_execution(&self) -> u16; // { 30303 }

    /// The p2p(tcp/udp protocol) listening port in the beacon side
    /// may be used in generating the ENR address for a beacon node
    fn get_sys_p2p_consensus_bn(&self) -> u16; // { 9000 }

    /// The p2p(quic protocol) listening port in the beacon side
    /// may be used in generating the ENR address for a beacon node
    fn get_sys_p2p_consensus_bn_quic(&self) -> u16; // { 9001 }

    /// The rpc listening port in the beacon side,
    /// usage(beacon): `--checkpoint-sync-url="http://${peer_ip}:5052"`
    fn get_sys_rpc_consensus_bn(&self) -> u16; // { 5052 }

    /// The engine API listening port in the execution side
    /// usage(beacon): `--execution-endpoints="http://localhost:8551"`
    fn get_sys_engine_api(&self) -> u16; // { 8551 }
}

pub trait NodeCmdGenerator<N, E>:
    Clone + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    /// Return: whether the target node is running
    fn cmd_is_running(&self, node: &N, env_meta: &E) -> Result<bool>;

    /// Return: the custom cmd to start the node
    fn cmd_for_start(&self, node: &N, env_meta: &E) -> String;

    /// Return: the custom cmd to stop the node
    fn cmd_for_stop(&self, node: &N, env_meta: &E, force: bool) -> String;

    /// Return: the custom cmd to migrate a node in
    fn cmd_for_migrate_in(&self, _src_node: &N, _dst_node: &N, _env_meta: &E) -> String {
        todo!()
    }

    /// Return: the custom cmd to migrate a node out
    fn cmd_for_migrate_out(
        &self,
        _src_node: &N,
        _dst_node: &N,
        _env_meta: &E,
    ) -> String {
        todo!()
    }
}

pub trait CustomOps:
    Clone + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    fn exec(&self, env_name: &EnvName) -> Result<()>;
}

impl CustomOps for () {
    fn exec(&self, _: &EnvName) -> Result<()> {
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

// global shared paths should not be used to avoid confusion
// when multiple users share a same physical machine
pub(crate) static BASE_DIR: LazyLock<String> = LazyLock::new(|| {
    let ret = env::var("RUNTIME_CHAIN_DEV_BASE_DIR").unwrap_or_else(|_| {
        format!(
            "/__chain_dev__/beacon_based/{}/{}/{}",
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

pub(crate) type BlockItv = u16;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum NodeKind {
    Bootstrap,
    ArchiveNode,
    FullNode,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Bootstrap => "bootstrap_node",
            Self::ArchiveNode => "archive_node",
            Self::FullNode => "full_node",
        };
        write!(f, "{}", msg)
    }
}
