//!
//! Localhost version
//!

use nix::{
    sys::socket::{
        self, AddressFamily, SockFlag, SockType, SockaddrIn, setsockopt, socket,
        sockopt,
    },
    unistd::{self, ForkResult},
};
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::io::AsRawFd,
    path::PathBuf,
    process::{Command, Stdio, exit},
    str::FromStr,
    sync::LazyLock,
};
use tendermint::{Genesis, validator::Info as TmValidator, vote::Power as TmPower};
use tendermint_config::{
    PrivValidatorKey as TmValidatorKey, TendermintConfig as TmConfig,
};
use toml_edit::{Array, DocumentMut as Document, value as toml_value};

pub use super::common::*;
use crate::common::NodeCmdGenerator;

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__DEV__", &*BASE_DIR));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    /// The name of this env
    pub name: EnvName,

    /// Which operation to trigger/call
    pub op: Op<A, C, P, U>,
}

impl<A, C, P, U> EnvCfg<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    pub fn exec<S>(&self, s: S) -> Result<()>
    where
        P: NodePorts,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        match &self.op {
            Op::Create { opts } => Env::<C, P, S>::create(self, opts, s).c(d!()),
            Op::Destroy { force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.destroy(*force).c(d!())),
            Op::DestroyAll { force } => Env::<C, P, S>::destroy_all(*force).c(d!()),
            Op::PushNode => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_node().c(d!())),
            Op::KickNode { node, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node(*node, *force).c(d!())),
            Op::Protect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start { node } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.start(*node).c(d!())),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop { node, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.stop(*node, *force).c(d!())),
            Op::StopAll { force } => Env::<C, P, S>::stop_all(*force).c(d!()),
            Op::Show => Env::<C, P, S>::load_env_by_cfg(self).c(d!()).map(|env| {
                env.show();
            }),
            Op::ShowAll => Env::<C, P, S>::show_all().c(d!()),
            Op::List => Env::<C, P, S>::list_all().c(d!()),
            Op::Custom(custom_op) => custom_op.exec(&self.name).c(d!()),
            Op::Nil(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct EnvMeta<C, N>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    N: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The name of this env
    #[serde(flatten)]
    pub name: EnvName,

    /// The data path of this env
    #[serde(rename = "env_home")]
    pub home: String,

    pub host_ip: String,

    #[serde(rename = "app_bin")]
    pub app_bin: String,

    pub app_extra_opts: String,

    #[serde(rename = "tendermint_bin")]
    pub tendermint_bin: String,

    pub tendermint_extra_opts: String,

    /// Seconds between two blocks
    #[serde(rename = "block_interval_in_seconds")]
    pub block_itv_secs: BlockItv,

    pub create_empty_block: bool,

    pub enable_tendermint_indexer: bool,

    #[serde(rename = "fuhrer_nodes")]
    pub fuhrers: BTreeMap<NodeID, N>,

    pub nodes: BTreeMap<NodeID, N>,

    /// The contents of `genesis.json` of all nodes
    #[serde(rename = "tendermint_genesis")]
    pub genesis: Option<Genesis>,

    pub custom_data: C,

    // The latest id of current nodes
    pub(crate) next_node_id: NodeID,
}

impl<C, P> EnvMeta<C, Node<P>>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
{
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        let mut list = vec![];

        let data_dir = format!("{}/envs", &*GLOBAL_BASE_DIR);
        fs::create_dir_all(&data_dir).c(d!())?;

        for entry in fs::read_dir(&data_dir).c(d!())? {
            let entry = entry.c(d!())?;
            let path = entry.path();
            if path.is_dir() {
                let env = path.file_name().c(d!())?.to_string_lossy().into_owned();
                list.push(env.into());
            }
        }

        list.sort();

        Ok(list)
    }

    pub fn load_env_by_name<S>(cfg_name: &EnvName) -> Result<Option<Env<C, P, S>>>
    where
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let p = format!("{}/envs/{}/CONFIG", &*GLOBAL_BASE_DIR, cfg_name);
        match fs::read_to_string(p) {
            Ok(d) => Ok(serde_json::from_str(&d).c(d!())?),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(eg!(e)),
            },
        }
    }

    pub fn get_addrports_any_node(&self) -> (&str, Vec<u16>) {
        let addr = self.host_ip.as_str();
        let node = self.fuhrers.values().chain(self.nodes.values()).next();
        let ports = pnk!(node).ports.get_port_list();
        (addr, ports)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<C, P, S>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    pub meta: EnvMeta<C, Node<P>>,
    pub is_protected: bool,

    #[serde(rename = "node_options_generator")]
    pub node_cmdline_generator: S,
}

impl<C, P, S> Env<C, P, S>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    // - Initilize a new env
    // - Create `genesis.json`
    fn create<A, U>(cfg: &EnvCfg<A, C, P, U>, opts: &EnvOpts<A, C>, s: S) -> Result<()>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        U: CustomOps,
    {
        let home = format!("{}/envs/{}", &*GLOBAL_BASE_DIR, &cfg.name);

        if opts.force_create {
            if let Ok(env) = Env::<C, P, S>::load_env_by_cfg(cfg) {
                env.destroy(true).c(d!())?;
            }
            omit!(fs::remove_dir_all(&home));
        }

        if fs::metadata(&home).is_ok() {
            return Err(eg!("Another env with the same name exists!"));
        }

        let mut env = Env {
            meta: EnvMeta {
                name: cfg.name.clone(),
                home,
                host_ip: opts.host_ip.clone(),
                app_bin: opts.app_bin.clone(),
                app_extra_opts: opts.app_extra_opts.clone(),
                tendermint_bin: opts.tendermint_bin.clone(),
                tendermint_extra_opts: opts.tendermint_extra_opts.clone(),
                block_itv_secs: opts.block_itv_secs,
                create_empty_block: opts.create_empty_block,
                enable_tendermint_indexer: opts.enable_tendermint_indexer,
                nodes: Default::default(),
                fuhrers: Default::default(),
                genesis: None,
                custom_data: opts.custom_data.clone(),
                next_node_id: Default::default(),
            },
            is_protected: true,
            node_cmdline_generator: s,
        };

        fs::create_dir_all(&env.meta.home).c(d!())?;

        macro_rules! add_initial_nodes {
            ($kind: tt) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, NodeKind::$kind).c(d!())?;
            }};
        }

        add_initial_nodes!(Fuhrer);
        for _ in 0..opts.initial_validator_num {
            add_initial_nodes!(Node);
        }

        env.gen_genesis(&opts.app_state)
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None).c(d!()))
    }

    // Destroy all nodes
    // - Stop all running processes
    // - Delete the data of every nodes
    fn destroy(&self, force: bool) -> Result<()> {
        if !force && self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        info_omit!(self.stop(None, true));
        sleep_ms!(100);

        for n in self.meta.fuhrers.values().chain(self.meta.nodes.values()) {
            n.clean().c(d!())?;
        }

        fs::remove_dir_all(&self.meta.home).c(d!())
    }

    // destroy all existing ENVs
    fn destroy_all(force: bool) -> Result<()> {
        for name in Self::get_env_list().c(d!())?.iter() {
            let env = Self::load_env_by_name(name)
                .c(d!())?
                .c(d!("BUG: env not found!"))?;
            env.destroy(force).c(d!())?;
        }

        Ok(())
    }

    // fuhrer nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(&mut self) -> Result<()> {
        let id = self.next_node_id();
        let kind = NodeKind::Node;
        self.alloc_resources(id, kind)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start(Some(id)).c(d!()))
    }

    // The fuhrer node should not be removed
    fn kick_node(&mut self, node_id: Option<NodeID>, force: bool) -> Result<()> {
        if !force && self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        let id = if let Some(id) = node_id {
            id
        } else {
            self.meta
                .nodes
                .keys()
                .rev()
                .copied()
                .next()
                .c(d!("no node found"))?
        };

        self.meta
            .nodes
            .remove(&id)
            .c(d!("Node ID does not exist?"))
            .and_then(|n| n.stop(self, true).c(d!()).and_then(|_| n.clean().c(d!())))
            .and_then(|_| self.write_cfg().c(d!()))
    }

    fn protect(&mut self) -> Result<()> {
        self.is_protected = true;
        self.write_cfg().c(d!())
    }

    fn unprotect(&mut self) -> Result<()> {
        self.is_protected = false;
        self.write_cfg().c(d!())
    }

    // Start one or all nodes
    fn start(&mut self, n: Option<NodeID>) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .fuhrers
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_peer_cfg()
            .c(d!())
            .and_then(|_| self.write_cfg().c(d!()))?;

        for i in ids.iter() {
            if let Some(n) = self.meta.fuhrers.get(i).or_else(|| self.meta.nodes.get(i))
            {
                n.start(self).c(d!())?;
            } else {
                return Err(eg!("not exist"));
            }
        }

        Ok(())
    }

    // Start all existing ENVs
    fn start_all() -> Result<()> {
        for env in Self::get_env_list().c(d!())?.iter() {
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .start(None)
                .c(d!())?;
        }
        Ok(())
    }

    // - Stop all processes
    // - Release all occupied ports
    fn stop(&self, n: Option<NodeID>, force: bool) -> Result<()> {
        let mut nodes = self.meta.fuhrers.values().chain(self.meta.nodes.values());

        let nodes = if let Some(id) = n {
            vec![nodes.find(|n| n.id == id).c(d!())?]
        } else {
            nodes.collect::<Vec<_>>()
        };

        nodes
            .into_iter()
            .map(|n| n.stop(self, force).c(d!()))
            .collect::<Result<Vec<_>>>()
            .map(|_| ())
    }

    // Stop all existing ENVs
    fn stop_all(force: bool) -> Result<()> {
        for env in Self::get_env_list().c(d!())?.iter() {
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .stop(None, force)
                .c(d!())?;
        }
        Ok(())
    }

    fn show(&self) {
        println!("{}", pnk!(serde_json::to_string_pretty(self)));
    }

    // show the details of all existing ENVs
    fn show_all() -> Result<()> {
        for (idx, env) in Self::get_env_list().c(d!())?.iter().enumerate() {
            println!("\x1b[31;01m====== ENV No.{} ======\x1b[00m", idx);
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .show();
            println!();
        }
        Ok(())
    }

    // list the names of all existing ENVs
    fn list_all() -> Result<()> {
        let list = Self::get_env_list().c(d!())?;

        if list.is_empty() {
            println!("\x1b[31;01mNo existing env!\x1b[00m");
        } else {
            println!("\x1b[31;01mEnv list:\x1b[00m");
            list.into_iter().for_each(|env| {
                println!("  {}", env);
            });
        }

        Ok(())
    }

    // 1. Allocate ports
    // 2. Change configs: ports, fuhrer address, etc
    // 3. Insert new node to the meta of env
    // 4. Write new configs of tendermint to disk
    fn alloc_resources(&mut self, id: NodeID, kind: NodeKind) -> Result<()> {
        // 1.
        let ports = self.alloc_ports(&kind).c(d!())?;

        // 2.
        let home = format!("{}/{}", self.meta.home, id);
        fs::create_dir_all(&home).c(d!())?;

        let cfg_path = format!("{}/config/config.toml", &home);
        let mut cfg = fs::read_to_string(&cfg_path)
            .c(d!())
            .or_else(|_| {
                cmd::exec_output(&format!(
                    "chmod +x {0} && {0} init --home {1}",
                    &self.meta.tendermint_bin, &home
                ))
                .c(d!())
                .and_then(|_| fs::read_to_string(&cfg_path).c(d!()))
            })
            .and_then(|c| c.parse::<Document>().c(d!()))?;

        cfg["proxy_app"] = toml_value(format!(
            "tcp://{}:{}",
            &self.meta.host_ip,
            ports.get_sys_abci()
        ));

        cfg["rpc"]["laddr"] = toml_value(format!(
            "tcp://{}:{}",
            &self.meta.host_ip,
            ports.get_sys_rpc()
        ));

        let mut arr = Array::new();
        arr.push("*");
        cfg["rpc"]["cors_allowed_origins"] = toml_value(arr);
        cfg["rpc"]["max_open_connections"] = toml_value(1000);

        // Maximum size of request body, in bytes,
        // set as ~300MB here
        cfg["rpc"]["max_body_bytes"] = toml_value(300_000_000);

        cfg["p2p"]["pex"] = toml_value(true);
        cfg["p2p"]["seed_mode"] = toml_value(false);
        cfg["p2p"]["addr_book_strict"] = toml_value(false);
        cfg["p2p"]["allow_duplicate_ip"] = toml_value(true);
        cfg["p2p"]["persistent_peers_max_dial_period"] = toml_value("30s");
        cfg["p2p"]["flush_throttle_timeout"] = toml_value("0ms");
        cfg["p2p"]["send_rate"] = toml_value(GB);
        cfg["p2p"]["recv_rate"] = toml_value(GB);
        cfg["p2p"]["max_packet_msg_payload_size"] = toml_value(MB);
        cfg["p2p"]["laddr"] = toml_value(format!(
            "tcp://{}:{}",
            &self.meta.host_ip,
            ports.get_sys_p2p()
        ));

        cfg["consensus"]["timeout_propose"] = toml_value("12s");
        cfg["consensus"]["timeout_propose_delta"] = toml_value("500ms");
        cfg["consensus"]["timeout_prevote"] = toml_value("0s");
        cfg["consensus"]["timeout_prevote_delta"] = toml_value("500ms");
        cfg["consensus"]["timeout_precommit"] = toml_value("0s");
        cfg["consensus"]["timeout_precommit_delta"] = toml_value("500ms");

        if self.meta.create_empty_block {
            let block_itv = self.meta.block_itv_secs.to_millisecond().c(d!())?;
            let itv = (block_itv / 2).to_string() + "ms";
            cfg["consensus"]["timeout_commit"] = toml_value(&itv);
            cfg["consensus"]["create_empty_blocks"] = toml_value(true);
            cfg["consensus"]["create_empty_blocks_interval"] = toml_value(itv);
        } else {
            // Avoid creating empty blocks,
            // also, we should not change the AppHash without new transactions
            cfg["consensus"]["timeout_commit"] = toml_value("0s");
            cfg["consensus"]["create_empty_blocks"] = toml_value(false);
            cfg["consensus"]["create_empty_blocks_interval"] = toml_value("0s");
        }

        cfg["mempool"]["recheck"] = toml_value(false);
        cfg["mempool"]["broadcast"] = toml_value(true);
        cfg["mempool"]["size"] = toml_value(100_000);
        cfg["mempool"]["cache_size"] = toml_value(200_000);
        cfg["mempool"]["max_txs_bytes"] = toml_value(GB);

        // Maximum size of a single transaction.
        cfg["mempool"]["max_tx_bytes"] = toml_value(250 * MB);

        cfg["mempool"]["ttl-num-blocks"] = toml_value(16);

        cfg["moniker"] = toml_value(format!("{}-{}", &self.meta.name, id));

        cfg["p2p"]["max_num_inbound_peers"] = toml_value(400);
        cfg["p2p"]["max_num_outbound_peers"] = toml_value(100);

        if self.meta.enable_tendermint_indexer {
            cfg["tx_index"]["indexer"] = toml_value("kv");
            cfg["tx_index"]["index_all_keys"] = toml_value(true);
        } else {
            cfg["tx_index"]["indexer"] = toml_value("null");
        }

        // 3.
        let node = Node {
            id,
            tm_id: TmConfig::load_toml_file(&cfg_path)
                .map_err(|e| eg!(e))?
                .load_node_key(&home)
                .map_err(|e| eg!(e))?
                .node_id()
                .to_string()
                .to_lowercase(),
            home: format!("{}/{}", &self.meta.home, id),
            kind,
            ports,
        };

        match kind {
            NodeKind::Node => self.meta.nodes.insert(id, node),
            NodeKind::Fuhrer => self.meta.fuhrers.insert(id, node),
        };

        // 4.
        fs::write(cfg_path, cfg.to_string()).c(d!())
    }

    // Global alloctor for ports
    fn alloc_ports(&self, node_kind: &NodeKind) -> Result<P> {
        let reserved_ports = P::reserved();

        let mut res = vec![];

        if matches!(node_kind, NodeKind::Fuhrer)
            && ENV_NAME_DEFAULT == self.meta.name.as_ref()
            && reserved_ports
                .iter()
                .copied()
                .all(|p| !pnk!(PortsCache::contains(p)) && port_is_free(p))
        {
            res = reserved_ports;
        } else {
            let mut cnter = 10000;
            while reserved_ports.len() > res.len() {
                let p = 20000 + rand::random::<u16>() % (65535 - 20000);
                if !reserved_ports.contains(&p)
                    && !PortsCache::contains(p).c(d!())?
                    && port_is_free(p)
                {
                    res.push(p);
                }
                cnter -= 1;
                alt!(0 == cnter, return Err(eg!("ports can not be allocated")))
            }
        }

        PortsCache::set(&res).c(d!())?;

        P::try_create(&res).c(d!())
    }

    fn update_peer_cfg(&self) -> Result<()> {
        for n in self.meta.nodes.values().chain(self.meta.fuhrers.values()) {
            let cfg_path = format!("{}/config/config.toml", &n.home);
            let mut cfg = fs::read_to_string(&cfg_path)
                .c(d!())
                .and_then(|c| c.parse::<Document>().c(d!()))?;
            cfg["p2p"]["persistent_peers"] = toml_value(
                self.meta
                    .nodes
                    .values()
                    .chain(self.meta.fuhrers.values())
                    .filter(|peer| peer.id != n.id)
                    .map(|n| {
                        format!(
                            "{}@{}:{}",
                            &n.tm_id,
                            &self.meta.host_ip,
                            n.ports.get_sys_p2p()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
            fs::write(cfg_path, cfg.to_string()).c(d!())?;
        }

        Ok(())
    }

    // Allocate unique IDs for nodes within the scope of an env
    fn next_node_id(&mut self) -> NodeID {
        let ret = self.meta.next_node_id;
        self.meta.next_node_id += 1;
        ret
    }

    // Generate a new `genesis.json`
    // based on the collection of initial validators
    fn gen_genesis<A>(&mut self, app_state: &A) -> Result<()>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    {
        let tmp_id = NodeID::MAX;
        let tmp_home = format!("{}/{}", &self.meta.home, tmp_id);

        let genit = |genesis_file: String| {
            self.meta
                .nodes
                .values()
                .map(|n| {
                    TmConfig::load_toml_file(&format!("{}/config/config.toml", &n.home))
                        .map_err(|e| eg!(e))
                        .and_then(|cfg| {
                            cfg.priv_validator_key_file
                                .as_ref()
                                .c(d!())
                                .and_then(|f| {
                                    PathBuf::from_str(&n.home).c(d!()).map(|p| {
                                        p.join(f).to_string_lossy().into_owned()
                                    })
                                })
                                .and_then(|p| {
                                    TmValidatorKey::load_json_file(&p)
                                        .map_err(|e| eg!(e))
                                })
                        })
                        .map(|key| {
                            TmValidator::new(key.pub_key, TmPower::from(PRESET_POWER))
                        })
                })
                .collect::<Result<Vec<_>>>()
                .and_then(|vs| serde_json::to_value(vs).c(d!()))
                .and_then(|mut vs| {
                    vs.as_array_mut().c(d!())?.iter_mut().enumerate().for_each(
                        |(i, v)| {
                            v["name"] = JsonValue::String(format!("node-{}", i));
                            v["power"] = JsonValue::String(PRESET_POWER.to_string());
                        },
                    );

                    fs::read_to_string(format!("{}/{}", tmp_home, genesis_file))
                        .c(d!())
                        .and_then(|g| serde_json::from_str::<JsonValue>(&g).c(d!()))
                        .and_then(|mut g| {
                            g["validators"] = vs;
                            g["app_state"] =
                                serde_json::to_value(app_state.clone()).c(d!())?;
                            g["consensus_params"]["block"]["max_bytes"] =
                                serde_json::to_value((MB * 300).to_string()).unwrap();
                            self.meta.genesis =
                                Some(serde_json::from_value(g).c(d!())?);
                            Ok(())
                        })
                })
        };

        cmd::exec_output(&format!(
            "chmod +x {0} && {0} init --home {1}",
            &self.meta.tendermint_bin, &tmp_home
        ))
        .c(d!())
        .and_then(|_| {
            TmConfig::load_toml_file(&format!("{}/config/config.toml", &tmp_home))
                .map_err(|e| eg!(e))
        })
        .and_then(|cfg| cfg.genesis_file.to_str().map(|f| f.to_owned()).c(d!()))
        .and_then(genit)
        .and_then(|_| fs::remove_dir_all(tmp_home).c(d!()))
    }

    // Apply genesis to one/all nodes in the same env
    fn apply_genesis(&mut self, n: Option<NodeID>) -> Result<()> {
        let nodes = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .fuhrers
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        for n in nodes.iter() {
            self.meta
                .nodes
                .get(n)
                .or_else(|| self.meta.fuhrers.get(n))
                .c(d!())
                .and_then(|n| {
                    TmConfig::load_toml_file(&format!("{}/config/config.toml", &n.home))
                        .map_err(|e| eg!(e))
                        .and_then(|cfg| {
                            PathBuf::from_str(&n.home)
                                .c(d!())
                                .map(|home| home.join(&cfg.genesis_file))
                        })
                        .and_then(|genesis_path| {
                            self.meta
                                .genesis
                                .as_ref()
                                .c(d!("BUG"))
                                .and_then(|g| serde_json::to_vec_pretty(g).c(d!()))
                                .and_then(|g| fs::write(genesis_path, g).c(d!()))
                        })
                })?;
        }

        Ok(())
    }

    #[inline(always)]
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        EnvMeta::<C, Node<P>>::get_env_list().c(d!())
    }

    fn load_env_by_cfg<A, U>(cfg: &EnvCfg<A, C, P, U>) -> Result<Env<C, P, S>>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        U: CustomOps,
    {
        Self::load_env_by_name(&cfg.name)
            .c(d!())
            .and_then(|env| match env {
                Some(env) => Ok(env),
                None => {
                    let msg = "ENV not found";
                    println!();
                    println!("********************");
                    println!("\x1b[01mHINTS: \x1b[33;01m{}\x1b[00m", msg);
                    println!("********************");
                    Err(eg!(msg))
                }
            })
    }

    #[inline(always)]
    pub fn load_env_by_name(cfg_name: &EnvName) -> Result<Option<Env<C, P, S>>> {
        EnvMeta::<C, Node<P>>::load_env_by_name(cfg_name).c(d!())
    }

    #[inline(always)]
    pub fn write_cfg(&self) -> Result<()> {
        let cfg = serde_json::to_vec_pretty(self).c(d!())?;
        fs::write(format!("{}/CONFIG", &self.meta.home), &cfg).c(d!())?;

        let cmd = format!(
            "cd {} && git add CONFIG && git commit -m '{}'",
            &self.meta.home,
            datetime!()
        );
        info_omit!(cmd::exec_output(&cmd), "No changes but try to commit?");
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    pub id: NodeID,
    #[serde(rename = "tendermint_node_id")]
    pub tm_id: String,
    #[serde(rename = "node_home")]
    pub home: String,
    pub kind: NodeKind,
    pub ports: P,
}

impl<P: NodePorts> Node<P> {
    fn start<C, S>(&self, env: &Env<C, P, S>) -> Result<()>
    where
        C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let cmd = env.node_cmdline_generator.cmd_cnt_running(self, &env.meta);
        let process_cnt = cmd::exec_output(&cmd)
            .c(d!(&cmd))?
            .trim()
            .parse::<u64>()
            .c(d!())?;

        if 0 < process_cnt {
            if 2 < process_cnt {
                // At least 3 processes is running, 'el'/'cl_bn'/'cl_vc'
                return Err(eg!(
                    "This node(ID {}) may be running, {} processes detected.",
                    self.id,
                    process_cnt
                ));
            } else {
                println!(
                    "This node(ID {}) may be in a partial failed state, less than 3 live processes({}) detected, enter the restart process.",
                    self.id, process_cnt
                );
                // Probably a partial failure
                self.stop(env, false).c(d!())?;
            }
        }

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Child) => {
                let cmd = env.node_cmdline_generator.cmd_for_start(self, &env.meta);
                pnk!(self.write_dev_log(&cmd));
                pnk!(exec_spawn(&cmd));
                exit(0);
            }
            Ok(_) => Ok(()),
            Err(_) => Err(eg!("fork failed!")),
        }
    }

    fn stop<C, S>(&self, env: &Env<C, P, S>, force: bool) -> Result<()>
    where
        C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let cmd = env
            .node_cmdline_generator
            .cmd_for_stop(self, &env.meta, force);
        let outputs = cmd::exec_output(&cmd).c(d!(&cmd))?;
        let contents = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&contents).c(d!())
    }

    fn write_dev_log(&self, cmd: &str) -> Result<()> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(format!("{}/mgmt.log", &self.home))
            .c(d!())
            .and_then(|mut f| {
                f.write_all(format!("\n\n[ {} ]\n", datetime!()).as_bytes())
                    .c(d!())
                    .and_then(|_| f.write_all(cmd.as_bytes()).c(d!()))
            })
    }

    // - Release all occupied ports
    // - Remove all files related to this node
    fn clean(&self) -> Result<()> {
        for port in self.ports.get_port_list().into_iter() {
            PortsCache::remove(port).c(d!())?;
        }
        fs::remove_dir_all(&self.home).c(d!())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum NodeKind {
    Node,
    Fuhrer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create { opts: EnvOpts<A, C> },
    Destroy { force: bool },
    DestroyAll { force: bool },
    PushNode,
    KickNode { node: Option<NodeID>, force: bool },
    Protect,
    Unprotect,
    Start { node: Option<NodeID> },
    StartAll,
    Stop { node: Option<NodeID>, force: bool },
    StopAll { force: bool },
    Show,
    ShowAll,
    List,
    Custom(U),
    Nil(P),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<A, C>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Default to '127.0.0.1'
    pub host_ip: String,

    /// Seconds between two blocks
    pub block_itv_secs: BlockItv,

    pub create_empty_block: bool,

    pub enable_tendermint_indexer: bool,

    /// How many initial validators should be created
    pub initial_validator_num: u8,

    pub app_bin: String,
    pub app_extra_opts: String,

    pub tendermint_bin: String,
    pub tendermint_extra_opts: String,

    pub force_create: bool,

    pub app_state: A,
    pub custom_data: C,
}

fn port_is_free(port: u16) -> bool {
    let ret = check_port(port);
    if ret.is_ok() {
        true
    } else {
        println!(
            "\n\x1b[33;01mNOTE: port {} can NOT be occupied!\x1b[00m",
            port
        );
        // info_omit!(ret);
        false
    }
}

fn check_port(port: u16) -> Result<()> {
    let check = |st: SockType| {
        let fd = socket(AddressFamily::Inet, st, SockFlag::empty(), None).c(d!())?;

        setsockopt(&fd, sockopt::ReuseAddr, &true)
            .c(d!())
            .and_then(|_| setsockopt(&fd, sockopt::ReusePort, &true).c(d!()))
            .and_then(|_| {
                socket::bind(fd.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, port)).c(d!())
            })
            .and_then(|_| unistd::close(fd.as_raw_fd()).c(d!()))
    };

    for st in [SockType::Datagram, SockType::Stream].into_iter() {
        check(st).c(d!())?;
    }

    Ok(())
}

fn exec_spawn(cmd: &str) -> Result<()> {
    Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .c(d!())?
        .wait()
        .c(d!())
        .map(|exit_status| {
            if !exit_status.success() {
                print_msg!("{}", cmd);
                println!("{exit_status}");
            }
        })
}

#[derive(Debug, Serialize, Deserialize)]
struct PortsCache {
    file_path: String,
    port_set: BTreeSet<u16>,
}

impl PortsCache {
    fn new() -> Self {
        Self {
            file_path: Self::file_path(),
            port_set: BTreeSet::new(),
        }
    }

    fn file_path() -> String {
        format!("{}/ports_cache", &*GLOBAL_BASE_DIR)
    }

    fn load() -> Result<Self> {
        match fs::read_to_string(Self::file_path()) {
            Ok(c) => serde_json::from_str(&c).c(d!()),
            Err(e) => {
                if ErrorKind::NotFound == e.kind() {
                    Ok(Self::new())
                } else {
                    Err(e).c(d!())
                }
            }
        }
    }

    fn write(&self) -> Result<()> {
        serde_json::to_string(self)
            .c(d!())
            .and_then(|c| fs::write(&self.file_path, c).c(d!()))
    }

    fn contains(port: u16) -> Result<bool> {
        Self::load().c(d!()).map(|i| i.port_set.contains(&port))
    }

    fn set(ports: &[u16]) -> Result<()> {
        let mut i = Self::load().c(d!())?;
        for p in ports {
            i.port_set.insert(*p);
        }
        i.write().c(d!())
    }

    fn remove(port: u16) -> Result<()> {
        let mut i = Self::load().c(d!())?;
        i.port_set.remove(&port);
        i.write().c(d!())
    }
}
