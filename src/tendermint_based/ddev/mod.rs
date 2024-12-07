//!
//! Distributed version
//!

pub mod remote;

use crate::check_errlist;
use crate::common::{
    hosts::{HostExpression, HostExpressionRef, HostID, HostMeta, Hosts, Weight},
    remote::{exec_cmds_on_hosts, get_file_from_hosts, put_file_to_hosts, Remote},
};
use rand::random;
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::ErrorKind,
    path::PathBuf,
    sync::LazyLock,
    thread,
};
use tendermint::{validator::Info as TmValidator, vote::Power as TmPower, Genesis};
use tendermint_config::{
    NodeKey, PrivValidatorKey as TmValidatorKey, TendermintConfig as TmConfig,
};
use toml_edit::{value as toml_value, Array, DocumentMut as Document};
use vsdb::MapxOrd;

pub use super::common::*;

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__D_DEV__", &*BASE_DIR));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    pub fn exec<S>(&self, s: S) -> Result<()>
    where
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        match &self.op {
            Op::Create { opts } => Env::<C, P, S>::create(self, opts, s).c(d!()),
            Op::Destroy { force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.destroy(*force).c(d!())),
            Op::DestroyAll { force } => Env::<C, P, S>::destroy_all(*force).c(d!()),
            Op::PushNode { host } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_node(host.as_ref()).c(d!())),
            Op::MigrateNode { node, host, force } => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        env.migrate_node(*node, host.as_ref(), *force).c(d!())
                    })
            }
            Op::KickNode { node, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node(*node, false, *force).c(d!())),
            Op::PushHosts { hosts } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_host(hosts.as_str()).c(d!())),
            Op::KickHost { host, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_host(host, *force).c(d!())),
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
            Op::HostPutFile {
                local_path,
                remote_path,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    put_file_to_hosts(
                        hosts,
                        local_path.as_str(),
                        remote_path.as_deref(),
                    )
                    .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_put_file(
                                local_path.as_str(),
                                remote_path.as_deref(),
                            )
                            .c(d!())
                        })
                }
            }
            Op::HostGetFile {
                remote_path,
                local_base_dir,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    get_file_from_hosts(
                        hosts,
                        remote_path.as_str(),
                        local_base_dir.as_deref(),
                    )
                    .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_get_file(
                                remote_path.as_str(),
                                local_base_dir.as_deref(),
                            )
                            .c(d!())
                        })
                }
            }
            Op::HostExec {
                cmd,
                script_path,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    exec_cmds_on_hosts(hosts, cmd.as_deref(), script_path.as_deref())
                        .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_exec(cmd.as_deref(), script_path.as_deref())
                                .c(d!())
                        })
                }
            }
            Op::Custom(custom_op) => custom_op.exec(&self.name).c(d!()),
            Op::Nil(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct EnvMeta<C, N>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    N: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The name of this env
    #[serde(flatten)]
    pub name: EnvName,

    /// The data path of this env
    #[serde(rename = "env_home")]
    pub home: String,

    #[serde(rename = "remote_hosts")]
    pub hosts: Hosts,

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
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
        match fs::read(p) {
            Ok(d) => Ok(serde_json::from_slice(&d).c(d!())?),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(eg!(e)),
            },
        }
    }

    pub fn get_addrports_any_node(&self) -> (&str, Vec<u16>) {
        let node = self.fuhrers.values().chain(self.nodes.values()).next();
        let node = pnk!(node);
        let addr = node.host.addr.connection_addr();
        let ports = node.ports.get_port_list();
        (addr, ports)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<C, P, S>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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

            omit!(fs::remove_dir_all(&home).c(d!()).and_then(|_| {
                let hdrs = opts
                    .hosts
                    .as_ref()
                    .values()
                    .map(|h| {
                        let h = h.clone();
                        let cmd = format!("rm -rf {}", &home);
                        thread::spawn(move || {
                            let remote = Remote::from(&h);
                            remote.exec_cmd(&cmd).c(d!(&h.meta.addr))
                        })
                    })
                    .collect::<Vec<_>>();

                let errlist = hdrs
                    .into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
                    .map(|e| e.unwrap_err())
                    .collect::<Vec<_>>();

                check_errlist!(errlist)
            }));
        }

        let remote_exists = || {
            let hdrs = opts
                .hosts
                .as_ref()
                .values()
                .map(|h| {
                    let h = h.clone();
                    let cmd = format!(r"\ls {}/*", &home);
                    thread::spawn(move || Remote::from(&h).exec_cmd(&cmd))
                })
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .any(|ret| ret.is_ok())
        };

        if fs::metadata(&home).is_ok() || remote_exists() {
            return Err(eg!("Another env with the same name exists!"));
        }

        let mut env = Env {
            meta: EnvMeta {
                name: cfg.name.clone(),
                home,
                hosts: opts.hosts.clone(),
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

        fs::create_dir_all(&env.meta.home).c(d!()).and_then(|_| {
            let hdrs = env
                .meta
                .hosts
                .as_ref()
                .values()
                .map(|h| {
                    let h = h.clone();
                    let cmd = format!("mkdir -p {}", &env.meta.home);
                    thread::spawn(move || {
                        let remote = Remote::from(&h);
                        info!(remote.exec_cmd(&cmd), &h.meta.addr)
                    })
                })
                .collect::<Vec<_>>();
            let errlist = hdrs
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>();
            check_errlist!(errlist)
        })?;

        macro_rules! add_initial_nodes {
            ($kind: tt) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, NodeKind::$kind, None).c(d!())?;
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

        let errlist = thread::scope(|s| {
            let hdrs = self
                .meta
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .map(|n| s.spawn(|| n.clean().c(d!())))
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(@errlist);

        fs::remove_dir_all(&self.meta.home).c(d!())?;

        let errlist = thread::scope(|s| {
            let hdrs = self
                .meta
                .hosts
                .as_ref()
                .values()
                .map(|h| {
                    s.spawn(move || {
                        let remote = Remote::from(h);
                        let cmd = format!("rm -rf {}", &self.meta.home);
                        info!(remote.exec_cmd(&cmd), &h.meta.addr)
                    })
                })
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    // Destroy all existing ENVs
    fn destroy_all(force: bool) -> Result<()> {
        for name in Self::get_env_list().c(d!())?.iter() {
            let env = Self::load_env_by_name(name)
                .c(d!())?
                .c(d!("BUG: env not found!"))?;

            if env.is_protected {
                print_msg!("This env({}) is protected, `unprotect` it first", name);
                continue;
            }

            env.destroy(force).c(d!())?;
        }

        Ok(())
    }

    fn push_node(&mut self, host: Option<&HostID>) -> Result<()> {
        self.push_node_data(NodeKind::Node, host)
            .c(d!())
            .and_then(|id| self.start(Some(id)).c(d!()))
    }

    fn push_node_data(
        &mut self,
        node_kind: NodeKind,
        host: Option<&HostID>,
    ) -> Result<NodeID> {
        let id = self.next_node_id();
        self.alloc_resources(id, node_kind, host)
            .c(d!())
            .and_then(|_| self.write_cfg().c(d!()))
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .map(|_| id)
    }

    // Migrate the target node to another host,
    // NOTE: the node ID will be reallocated
    fn migrate_node(
        &mut self,
        node_id: NodeID,
        new_host: Option<&HostID>,
        force: bool,
    ) -> Result<()> {
        if !force && self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        let old_node = self
            .meta
            .fuhrers
            .get(&node_id)
            .or_else(|| self.meta.nodes.get(&node_id))
            .c(d!("The target node does not exist"))?
            .clone();

        let new_host = if let Some(id) = new_host {
            id.clone()
        } else {
            let mut seq = self
                .meta
                .hosts
                .as_ref()
                .values()
                .map(|h| (h.meta.clone(), h.weight))
                .max_by(|a, b| a.1.cmp(&b.1))
                .c(d!("BUG"))
                .map(|(_, max_weight)| {
                    self.meta
                        .hosts
                        .as_ref()
                        .values()
                        .filter(|h| h.weight > 0)
                        .map(|h| {
                            (
                                h.meta.clone(),
                                (h.node_cnt as Weight * max_weight) / h.weight,
                            )
                        })
                        .collect::<Vec<_>>()
                })?;
            seq.sort_by(|a, b| a.1.cmp(&b.1));
            seq.into_iter()
                .find(|h| h.0.addr != old_node.host.addr)
                .c(d!("no avaliable hosts left, migrate failed"))
                .map(|h| h.0.host_id())?
        };

        if old_node.host.host_id() == new_host {
            return Err(eg!("The host where the two nodes are located is the same"));
        }

        let new_node_id = self
            .push_node_data(old_node.kind, Some(&new_host))
            .c(d!())?;
        let new_node = self
            .meta
            .fuhrers
            .get(&new_node_id)
            .or_else(|| self.meta.nodes.get(&new_node_id))
            .c(d!("BUG"))?;

        old_node
            .migrate(new_node, self)
            .c(d!())
            .or_else(|_| {
                self.kick_node(Some(new_node_id), true, force)
                    .c(d!())
                    .map(|_| ())
            })
            .and_then(|_| self.kick_node(Some(node_id), true, force).c(d!()))
    }

    // The fuhrer node should not be removed
    fn kick_node(
        &mut self,
        node_id: Option<NodeID>,
        migrate: bool,
        force: bool,
    ) -> Result<()> {
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
                .fuhrers
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .next_back()
                .c(d!("no node found"))?
        };

        if !migrate && self.meta.fuhrers.contains_key(&id) {
            return Err(eg!(
                "Node-[{}] is a fuhrer node, deny to kick except in migration",
                id
            ));
        }

        self.meta
            .nodes
            .remove(&id)
            .or_else(|| self.meta.fuhrers.remove(&id))
            .c(d!("Node ID does not exist?"))
            .and_then(|n| {
                self.meta
                    .hosts
                    .as_mut()
                    .get_mut(&n.host.host_id())
                    .unwrap()
                    .node_cnt -= 1;
                n.stop(self, true).c(d!()).and_then(|_| n.clean().c(d!()))
            })
            .and_then(|_| self.write_cfg().c(d!()))
    }

    fn push_host(&mut self, host_expression: HostExpressionRef) -> Result<()> {
        let mut new_hosts = hosts::param_parse_hosts(host_expression).c(d!())?;
        if self
            .meta
            .hosts
            .as_ref()
            .keys()
            .any(|addr| new_hosts.contains_key(addr))
        {
            return Err(eg!("One or more hosts already exist"));
        }
        self.meta.hosts.as_mut().append(&mut new_hosts);
        self.write_cfg().c(d!())
    }

    fn kick_host(&mut self, host: &HostID, force: bool) -> Result<()> {
        if !force && self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        if force {
            if 2 > self.meta.hosts.as_ref().len() {
                return Err(eg!("Host insufficient(num <= 1), add more hosts first!"));
            }
            let nodes_to_migrate = self
                .meta
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .filter(|n| &n.host.host_id() == host)
                .map(|n| n.id)
                .collect::<BTreeSet<_>>();
            for id in nodes_to_migrate.into_iter() {
                self.migrate_node(id, None, force).c(d!())?;
            }
        } else if let Some(n) = self.meta.hosts.as_ref().get(host).map(|h| h.node_cnt) {
            if 0 < n {
                return Err(eg!("Some nodes are running on this host!"));
            }
        } else {
            return Err(eg!("The target host does not exist!"));
        }

        self.meta.hosts.as_mut().remove(host);
        self.write_cfg().c(d!())
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

        self.update_peer_cfg().c(d!())?;

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for i in ids.iter() {
                let hdr = s.spawn(|| {
                    if let Some(n) =
                        self.meta.fuhrers.get(i).or_else(|| self.meta.nodes.get(i))
                    {
                        n.start(self).c(d!())
                    } else {
                        Err(eg!("not exist"))
                    }
                });
                hdrs.push(hdr);
            }
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
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

        let errlist = thread::scope(|s| {
            let hdrs = nodes
                .into_iter()
                .map(|n| s.spawn(|| info!(n.stop(self, force), &n.host.addr)))
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
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
        dbg!(self);
    }

    // Show the details of all existing ENVs
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

    // List the names of all existing ENVs
    fn list_all() -> Result<()> {
        let list = Self::get_env_list().c(d!())?;

        if list.is_empty() {
            eprintln!("\x1b[31;01mNo existing env!\x1b[00m");
        } else {
            println!("\x1b[31;01mEnv list:\x1b[00m");
            list.into_iter().for_each(|env| {
                println!("  {}", env);
            });
        }

        Ok(())
    }

    #[inline(always)]
    fn hosts_put_file(
        &self,
        local_path: &str,
        remote_path: Option<&str>,
    ) -> Result<()> {
        put_file_to_hosts(&self.meta.hosts, local_path, remote_path).c(d!())
    }

    #[inline(always)]
    fn hosts_get_file(
        &self,
        remote_path: &str,
        local_base_dir: Option<&str>,
    ) -> Result<()> {
        get_file_from_hosts(&self.meta.hosts, remote_path, local_base_dir).c(d!())
    }

    #[inline(always)]
    fn hosts_exec(&self, cmd: Option<&str>, script_path: Option<&str>) -> Result<()> {
        exec_cmds_on_hosts(&self.meta.hosts, cmd, script_path).c(d!())
    }

    // 1. Allocate host and ports
    // 2. Change configs: ports, fuhrer address, etc
    // 3. Write new configs of tendermint to local/remote disk
    // 4. Insert new node to the meta of env
    fn alloc_resources(
        &mut self,
        id: NodeID,
        kind: NodeKind,
        host: Option<&HostID>,
    ) -> Result<()> {
        self.alloc_hosts_ports(&kind, host) // 1.
            .c(d!())
            .and_then(|(host, ports)| {
                self.apply_resources(id, kind, host, ports).c(d!()) // 2. 3. 4.
            })
            .map(|node| {
                match kind {
                    NodeKind::Fuhrer => self.meta.fuhrers.insert(id, node),
                    NodeKind::Node => self.meta.nodes.insert(id, node),
                };
            })
    }

    fn apply_resources(
        &self,
        id: NodeID,
        kind: NodeKind,
        host: HostMeta,
        ports: P,
    ) -> Result<Node<P>> {
        let remote = Remote::from(&host);

        // 2.
        let home = format!("{}/{}", self.meta.home, id);
        remote.exec_cmd(&format!("mkdir -p {}", &home)).c(d!())?;

        let cfgfile = format!("{}/config/config.toml", &home);
        let cmd = format!(
            "chmod +x {0} && {0} init --home {1} && rm -f {1}/config/addrbook.json",
            &self.meta.tendermint_bin, &home
        );
        let mut cfg = remote
            .exec_cmd(&cmd)
            .c(d!(cmd))
            .and_then(|_| remote.read_file(&cfgfile).c(d!(cfgfile)))
            .and_then(|c| c.parse::<Document>().c(d!()))?;

        cfg["proxy_app"] = toml_value(format!(
            "tcp://{}:{}",
            &host.addr.local_ip,
            ports.get_sys_abci()
        ));

        cfg["rpc"]["laddr"] = toml_value(format!(
            "tcp://{}:{}",
            &host.addr.local_ip,
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
            &host.addr.local_ip,
            ports.get_sys_p2p()
        ));

        if let Some(addr_ext_ip) = host.addr.ext_ip.as_ref() {
            cfg["p2p"]["external_address"] =
                toml_value(format!("{}:{}", &addr_ext_ip, ports.get_sys_p2p()));
        }

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

        let cfg = cfg.to_string();

        // 3.
        remote.replace_file(&cfgfile, cfg.as_bytes()).c(d!())?;

        // 4.
        let tm_id = TmConfig::parse_toml(&cfg)
            .map_err(|e| eg!(e))
            .and_then(|cfg| {
                remote
                    .read_file(PathBuf::from(&home).join(cfg.node_key_file))
                    .c(d!())
            })
            .and_then(|contents| NodeKey::parse_json(contents).c(d!()))?
            .node_id()
            .to_string()
            .to_lowercase();
        let node = Node {
            id,
            tm_id,
            home: format!("{}/{}", &self.meta.home, id),
            kind,
            host,
            ports,
        };

        Ok(node)
    }

    fn update_peer_cfg(&self) -> Result<()> {
        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for n in self.meta.nodes.values().chain(self.meta.fuhrers.values()) {
                let hdr = s.spawn(|| {
                    let remote = Remote::from(&n.host);
                    let cfgfile = format!("{}/config/config.toml", &n.home);
                    let mut cfg = remote
                        .read_file(&cfgfile)
                        .c(d!())
                        .and_then(|c| c.parse::<Document>().c(d!()))?;
                    cfg["p2p"]["persistent_peers"] = toml_value(
                        self.meta
                            .nodes
                            .values()
                            .chain(self.meta.fuhrers.values())
                            .filter(|p| p.id != n.id)
                            .map(|p| {
                                format!(
                                    "{}@{}:{}",
                                    &p.tm_id,
                                    p.host.addr.connection_addr(),
                                    p.ports.get_sys_p2p()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    remote
                        .replace_file(&cfgfile, cfg.to_string().as_bytes())
                        .c(d!())
                });
                hdrs.push(hdr);
            }
            hdrs.into_iter()
                .flat_map(|hdr| hdr.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
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

        let parse = |n: &Node<P>| {
            let cfgfile = format!("{}/config/config.toml", &n.home);
            let remote = Remote::from(&n.host);
            remote
                .read_file(cfgfile)
                .c(d!())
                .and_then(|f| TmConfig::parse_toml(f).map_err(|e| eg!(e)))
                .and_then(|cfg| {
                    cfg.priv_validator_key_file
                        .as_ref()
                        .c(d!())
                        .and_then(|f| {
                            remote.read_file(PathBuf::from(&n.home).join(f)).c(d!())
                        })
                        .and_then(|c| TmValidatorKey::parse_json(c).map_err(|e| eg!(e)))
                })
                .map(|key| TmValidator::new(key.pub_key, TmPower::from(PRESET_POWER)))
        };
        let gen = |genesis_file: String| {
            thread::scope(|s| {
                let hdrs = self
                    .meta
                    .nodes
                    .values()
                    .map(|n| s.spawn(|| parse(n)))
                    .collect::<Vec<_>>();
                hdrs.into_iter()
                    .flat_map(|h| h.join())
                    .collect::<Result<Vec<_>>>()
            })
            .and_then(|vs| serde_json::to_value(vs).c(d!()))
            .and_then(|mut vs| {
                vs.as_array_mut()
                    .c(d!())?
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, v)| {
                        v["power"] = JsonValue::String(PRESET_POWER.to_string());
                        v["name"] = JsonValue::String(format!("NODE_{}", i));
                    });

                fs::read_to_string(format!("{}/{}", tmp_home, genesis_file))
                    .c(d!())
                    .and_then(|g| serde_json::from_str::<JsonValue>(&g).c(d!()))
                    .and_then(|mut g| {
                        g["validators"] = vs;
                        g["app_state"] =
                            serde_json::to_value(app_state.clone()).c(d!())?;
                        g["genesis_time"] = JsonValue::String(
                            // '2022-xxx' --> '1022-xxx'
                            // avoid waiting time between hosts
                            // due to different time shift
                            // when the chain is starting first time
                            g["genesis_time"].as_str().unwrap().replacen('2', "1", 1),
                        );
                        g["consensus_params"]["block"]["max_bytes"] =
                            serde_json::to_value((MB * 300).to_string()).unwrap();
                        self.meta.genesis = Some(serde_json::from_value(g).c(d!())?);
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
        .and_then(gen)
        .and_then(|_| fs::remove_dir_all(tmp_home).c(d!()))
    }

    fn apply_genesis(&self, n: Option<NodeID>) -> Result<()> {
        let nodes = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .fuhrers
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for n in nodes.iter() {
                let hdr = s.spawn(|| {
                    let n = self
                        .meta
                        .nodes
                        .get(n)
                        .or_else(|| self.meta.fuhrers.get(n))
                        .c(d!())?;
                    let remote = Remote::from(&n.host);
                    let cfgfile = format!("{}/config/config.toml", &n.home);
                    remote
                        .read_file(cfgfile)
                        .c(d!())
                        .and_then(|c| TmConfig::parse_toml(c).map_err(|e| eg!(e)))
                        .map(|cfg| PathBuf::from(&n.home).join(cfg.genesis_file))
                        .and_then(|genesis_path| {
                            self.meta
                                .genesis
                                .as_ref()
                                .c(d!("BUG"))
                                .and_then(|g| serde_json::to_vec_pretty(g).c(d!()))
                                .and_then(|g| {
                                    remote.replace_file(&genesis_path, &g).c(d!())
                                })
                        })
                });
                hdrs.push(hdr);
            }
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .map(|e| e.unwrap_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
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
                    eprintln!();
                    eprintln!("********************");
                    eprintln!(
                        "\x1b[01mHINTS: \x1b[33;01mENV({}) NOT FOUND\x1b[00m",
                        &cfg.name
                    );
                    eprintln!("********************");
                    Err(eg!("ENV({}) NOT FOUND", &cfg.name))
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

    // Alloc <host,ports> for a new node
    fn alloc_hosts_ports(
        &mut self,
        node_kind: &NodeKind,
        host_id: Option<&HostID>,
    ) -> Result<(HostMeta, P)> {
        let host = self.alloc_host(node_kind, host_id).c(d!())?;
        let ports = self.alloc_ports(node_kind, &host).c(d!())?;
        Ok((host, ports))
    }

    fn alloc_host(
        &mut self,
        node_kind: &NodeKind,
        host: Option<&HostID>,
    ) -> Result<HostMeta> {
        if let Some(id) = host {
            return self
                .meta
                .hosts
                .as_ref()
                .get(id)
                .c(d!())
                .map(|h| h.meta.clone());
        }

        let (max_host, max_weight) = self
            .meta
            .hosts
            .as_ref()
            .values()
            .map(|h| (h.meta.clone(), h.weight))
            .max_by(|a, b| a.1.cmp(&b.1))
            .c(d!("BUG"))?;

        let h = if matches!(node_kind, NodeKind::Fuhrer) {
            max_host
        } else {
            let mut seq = self
                .meta
                .hosts
                .as_ref()
                .values()
                .filter(|h| h.weight > 0)
                .map(|h| {
                    (
                        h.meta.clone(),
                        (h.node_cnt as Weight * max_weight) / h.weight,
                    )
                })
                .collect::<Vec<_>>();
            seq.sort_by(|a, b| a.1.cmp(&b.1));
            seq.into_iter().next().c(d!()).map(|h| h.0)?
        };

        self.meta
            .hosts
            .as_mut()
            .get_mut(&h.host_id())
            .unwrap()
            .node_cnt += 1;

        Ok(h)
    }

    fn alloc_ports(&self, _node_kind: &NodeKind, host: &HostMeta) -> Result<P> {
        let reserved_ports = P::reserved();
        let reserved = reserved_ports
            .iter()
            .map(|p| format!("{},{}", &host.addr, p))
            .collect::<Vec<_>>();
        let remote = Remote::from(host);

        let occupied = remote.get_occupied_ports().c(d!())?;
        let port_is_free = |p: &u16| !occupied.contains(p);

        let mut res = vec![];

        if reserved.iter().all(|hp| !PC.contains(hp))
            && reserved_ports.iter().all(port_is_free)
        {
            res = reserved_ports;
        } else {
            let mut cnter = 10000;
            while reserved.len() > res.len() {
                let p = 20000 + random::<u16>() % (65535 - 20000);
                let hp = format!("{},{}", &host.addr, p);
                if !res.contains(&p)
                    && !reserved_ports.contains(&p)
                    && !PC.contains(&hp)
                    && port_is_free(&p)
                {
                    res.push(p);
                }
                cnter -= 1;
                alt!(0 == cnter, return Err(eg!("ports can not be allocated")))
            }
        }

        PC.set(
            &res.iter()
                .map(|p| format!("{},{}", &host.addr, p))
                .collect::<Vec<_>>(),
        );

        P::try_create(&res).c(d!())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    id: NodeID,
    #[serde(rename = "tendermint_node_id")]
    tm_id: String,
    #[serde(rename = "node_home")]
    pub home: String,
    pub kind: NodeKind,
    pub host: HostMeta,
    pub ports: P,
}

impl<P: NodePorts> Node<P> {
    fn start<C, S>(&self, env: &Env<C, P, S>) -> Result<()>
    where
        C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let cmd = env.node_cmdline_generator.cmd_cnt_running(self, &env.meta);
        let process_cnt = Remote::from(&self.host)
            .exec_cmd(&cmd)
            .c(d!())?
            .trim()
            .parse::<u64>()
            .c(d!())?;
        if 0 < process_cnt {
            if 2 < process_cnt {
                // At least 3 processes is running, 'el'/'cl_bn'/'cl_vc'
                return Err(eg!(
                    "This node(ID {}, HOST {}) may be running, {} processes detected.",
                    self.id,
                    self.host.host_id(),
                    process_cnt
                ));
            } else {
                println!(
                    "This node(ID {}, HOST {}) may be in a partial failed state, less than 3 live processes({}) detected, enter the restart process.",
                    self.id,
                    self.host.host_id(),
                    process_cnt
                );
                // Probably a partial failure
                self.stop(env, false).c(d!())?;
            }
        }

        let cmd = env.node_cmdline_generator.cmd_for_start(self, &env.meta);
        let outputs = Remote::from(&self.host).exec_cmd(&cmd).c(d!(cmd))?;
        let log = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&log).c(d!())
    }

    fn stop<C, S>(&self, env: &Env<C, P, S>, force: bool) -> Result<()>
    where
        C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let cmd = env
            .node_cmdline_generator
            .cmd_for_stop(self, &env.meta, force);
        let outputs = Remote::from(&self.host).exec_cmd(&cmd).c(d!())?;
        let log = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&log).c(d!())
    }

    fn write_dev_log(&self, log: &str) -> Result<()> {
        let log = format!("\n\n[ {} ]\n{}: {}", datetime!(), &self.host.addr, log);
        let logfile = format!("{}/mgmt.log", &self.home);
        Remote::from(&self.host)
            .append_file(logfile, log.as_bytes())
            .c(d!())
    }

    // - Release all occupied ports
    // - Remove all files related to this node
    fn clean(&self) -> Result<()> {
        for port in self.ports.get_port_list().iter() {
            PC.remove(&format!("{},{}", &self.host.addr, port));
        }

        // Remove all related files
        Remote::from(&self.host)
            .exec_cmd(&format!("rm -rf {}", &self.home))
            .c(d!())
            .map(|_| ())
    }

    // Migrate this node to another host,
    // NOTE: the node ID has been changed
    fn migrate<C, S>(&self, new_node: &Node<P>, env: &Env<C, P, S>) -> Result<()>
    where
        C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        if self.host.addr == new_node.host.addr {
            return Err(eg!("The host where the two nodes are located is the same"));
        }

        // Fix me:
        // only the validator client data need to be reserved,
        // need to wait for the graceful exiting process ?
        self.stop(env, false).c(d!())?;

        let migrate_fn = env
            .node_cmdline_generator
            .cmd_for_migrate(self, new_node, &env.meta);

        migrate_fn().c(d!())
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum NodeKind {
    Node,
    Fuhrer,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Fuhrer => "fuhrer",
            Self::Node => "node",
        };
        write!(f, "{}", msg)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create {
        opts: EnvOpts<A, C>,
    },
    Destroy {
        force: bool,
    },
    DestroyAll {
        force: bool,
    },
    PushNode {
        host: Option<HostID>,
    },
    MigrateNode {
        node: NodeID,
        host: Option<HostID>,
        force: bool,
    },
    KickNode {
        node: Option<NodeID>,
        force: bool,
    },
    // remote_host_addr|remote_host_addr_ext_ip#ssh_user#ssh_remote_port#weight#ssh_local_privkey
    PushHosts {
        hosts: HostExpression,
    },
    KickHost {
        host: HostID,
        force: bool,
    },
    Protect,
    Unprotect,
    Start {
        node: Option<NodeID>,
    },
    StartAll,
    Stop {
        node: Option<NodeID>,
        force: bool,
    },
    StopAll {
        force: bool,
    },
    Show,
    ShowAll,
    List,
    HostPutFile {
        local_path: String,
        remote_path: Option<String>,
        hosts: Option<Hosts>,
    },
    HostGetFile {
        remote_path: String,
        local_base_dir: Option<String>,
        hosts: Option<Hosts>,
    },
    HostExec {
        cmd: Option<String>,
        script_path: Option<String>,
        hosts: Option<Hosts>,
    },
    Custom(U),
    Nil(P),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<A, C>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The host list of the env
    pub hosts: Hosts,

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

static PC: LazyLock<PortsCache> = LazyLock::new(|| pnk!(PortsCache::load_or_create()));

#[derive(Serialize, Deserialize)]
struct PortsCache {
    vsdb_base_dir: String,
    // [ <remote addr + remote port> ]
    port_set: MapxOrd<String, ()>,
}

impl PortsCache {
    fn load_or_create() -> Result<Self> {
        let vbd = format!("{}/ports_cache", &*GLOBAL_BASE_DIR);
        vsdb::vsdb_set_base_dir(&vbd).c(d!())?;

        let meta_path = format!("{}/meta.json", &vbd);

        let ret = match fs::read(&meta_path) {
            Ok(c) => serde_json::from_slice(&c).c(d!())?,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    let r = Self {
                        vsdb_base_dir: vbd,
                        port_set: MapxOrd::new(),
                    };
                    serde_json::to_vec(&r)
                        .c(d!())
                        .and_then(|c| fs::write(meta_path, c).c(d!()))?;
                    r
                }
                _ => return Err(e).c(d!()),
            },
        };
        Ok(ret)
    }

    fn contains(&self, port: &str) -> bool {
        self.port_set.contains_key(&port.to_owned())
    }

    fn set(&self, ports: &[String]) {
        for p in ports {
            assert!(unsafe { self.port_set.shadow() }
                .insert(&p.to_owned(), &())
                .is_none());
        }
    }

    fn remove(&self, port: &str) {
        unsafe { self.port_set.shadow() }.remove(&port.to_owned());
    }
}
