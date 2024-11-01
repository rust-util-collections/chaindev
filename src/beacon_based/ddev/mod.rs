//!
//! Distributed version
//!

pub mod remote;

use crate::check_errlist;
use crate::common::{
    hosts::{Host, HostAddr, HostID, HostMeta, Hosts},
    remote::{exec_cmds_on_hosts, get_file_from_hosts, put_file_to_hosts, Remote},
};
use parking_lot::RwLock;
use rand::random;
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    io::ErrorKind,
    sync::LazyLock,
    thread,
};
use vsdb::MapxOrd;

pub use super::common::*;

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__D_DEV__", &*BASE_DIR));

static OCCUPIED_PORTS: LazyLock<RwLock<BTreeMap<HostID, BTreeSet<u16>>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<C, P, U>
where
    C: CustomData,
    P: NodePorts,
    U: CustomOps,
{
    /// The name of this env
    pub name: EnvName,

    /// Which operation to trigger/call
    pub op: Op<C, P, U>,
}

impl<C, P, U> EnvCfg<C, P, U>
where
    C: CustomData,
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
                .and_then(|mut env| env.destroy(*force).c(d!())),
            Op::DestroyAll { force } => Env::<C, P, S>::destroy_all(*force).c(d!()),
            Op::PushNodes {
                host,
                custom_data,
                fullnode,
                num,
            } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    env.push_nodes(
                        alt!(*fullnode, NodeKind::FullNode, NodeKind::ArchiveNode,),
                        Some(custom_data.clone()),
                        host.as_ref(),
                        *num,
                    )
                    .c(d!())
                }),
            Op::MigrateNodes { nodes, host } => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        // `rev()`: migrate newer nodes(bigger id) at first
                        for (i, id) in nodes.iter().rev().enumerate() {
                            env.migrate_node(*id, host.as_ref()).c(d!())?;
                            println!(
                                "The {}th node has been migrated, NodeID: {id}",
                                1 + i
                            );
                        }
                        Ok(())
                    })
            }
            Op::KickNodes { nodes, num } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = nodes {
                        for (i, id) in ids.iter().rev().copied().enumerate() {
                            let id_returned = env.kick_node(Some(id)).c(d!())?;
                            assert_eq!(id, id_returned);
                            println!(
                                "The {}th node has been kicked, NodeID: {id}",
                                1 + i
                            );
                        }
                    } else {
                        for i in 1..=*num {
                            let id = env.kick_node(None).c(d!())?;
                            println!("The {i}th node has been kicked, NodeID: {id}",);
                        }
                    }
                    Ok(())
                }),
            Op::PushHosts { hosts } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_hosts(hosts).c(d!())),
            Op::KickHosts { hosts, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    for (i, id) in hosts.iter().enumerate() {
                        let removed_host = env
                            .kick_host(id, *force)
                            .c(d!())
                            .and_then(|h| serde_json::to_string(&h).c(d!()))?;
                        println!(
                            "The {i}th host has been kicked, host info: {removed_host}"
                        );
                    }
                    Ok(())
                }),
            Op::Protect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start {
                nodes,
                ignore_failed,
                realloc_ports,
            } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = nodes {
                        env.start(
                            Some(ids.iter().copied().collect()),
                            *ignore_failed,
                            *realloc_ports,
                        )
                        .c(d!())
                    } else {
                        env.start(None, *ignore_failed, *realloc_ports).c(d!())
                    }
                }),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop { nodes, force } => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = nodes {
                        env.stop(Some(ids), *force).c(d!())
                    } else {
                        env.stop(None, *force).c(d!())
                    }
                }),
            Op::StopAll { force } => Env::<C, P, S>::stop_all(*force).c(d!()),
            Op::DebugFailedNodes => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.debug_failed_nodes().c(d!())),
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
    C: CustomData,
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

    /// Seconds between two blocks
    #[serde(rename = "block_time_in_seconds")]
    pub block_itv: BlockItv,

    /// The contents of a EGG custom.env,
    ///
    /// Format:
    /// - https://github.com/rust-util-collections/EGG/blob/master/custom.env.example
    pub genesis_pre_settings: String,

    /// The network cfg files,
    /// a gzip compressed tar package
    pub genesis: Vec<u8>,

    /// The initial validator keys,
    /// a gzip compressed tar package
    pub genesis_vkeys: Vec<u8>,

    /// A 24-word bip39 mnemonic
    /// where the initial validators are derived from
    pub genesis_mnemonic_words: String,

    /// How many validators registered on the fuhrer nodes
    pub genesis_validator_num: u16,

    /// Address of the deposit contract
    pub deposit_contract_addr: String,

    /// `$EL_PREMINE_ADDRS` of the EGG repo
    pub premined_accounts: JsonValue,

    /// The first Fuhrer node
    /// will be treated as the genesis node
    #[serde(rename = "fuhrer_nodes")]
    pub fuhrers: BTreeMap<NodeID, N>,

    /// Non-fuhrer node collection
    pub nodes: BTreeMap<NodeID, N>,

    /// An in-memory cache for recording node status,
    pub nodes_should_be_online: MapxOrd<NodeID, ()>,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: C,

    // Node ID allocator
    next_node_id: NodeID,
}

impl<C, P> EnvMeta<C, Node<P>>
where
    C: CustomData,
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
    C: CustomData,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    pub meta: EnvMeta<C, Node<P>>,
    pub is_protected: bool,
    pub node_cmdline_generator: S,
}

impl<C, P, S> Env<C, P, S>
where
    C: CustomData,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    // - Initilize a new env
    // - Create `genesis.json`
    fn create<U>(cfg: &EnvCfg<C, P, U>, opts: &EnvOpts<C>, s: S) -> Result<()>
    where
        U: CustomOps,
    {
        let home = format!("{}/envs/{}", &*GLOBAL_BASE_DIR, &cfg.name);

        if opts.force_create {
            if let Ok(mut env) = Env::<C, P, S>::load_env_by_cfg(cfg) {
                env.destroy(true).c(d!())?;
            }

            omit!(fs::remove_dir_all(&home));

            let force_clean_up = || -> Result<()> {
                let mut errlist = vec![];

                // Use chunks to avoid resource overload
                for hosts in opts.hosts.as_ref().values().collect::<Vec<_>>().chunks(24)
                {
                    thread::scope(|s| {
                        hosts
                            .iter()
                            .map(|h| {
                                let cmd = format!("rm -rf {}", &home);
                                s.spawn(move || {
                                    let remote = Remote::from(*h);
                                    info!(remote.exec_cmd(&cmd), &h.meta.addr)
                                })
                            })
                            .collect::<Vec<_>>()
                            .into_iter()
                            .flat_map(|h| h.join())
                            .for_each(|t| {
                                if let Err(e) = t {
                                    errlist.push(e);
                                }
                            });
                    });
                }

                check_errlist!(errlist)
            };

            omit!(force_clean_up());
        };

        let remote_exists = || {
            for hosts in opts.hosts.as_ref().values().collect::<Vec<_>>().chunks(24) {
                let exists = thread::scope(|s| {
                    hosts
                        .iter()
                        .map(|h| {
                            let cmd = format!(r"\ls {}/*", &home);
                            s.spawn(move || Remote::from(*h).exec_cmd(&cmd))
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .flat_map(|h| h.join())
                        .any(|ret| ret.is_ok())
                });

                alt!(exists, return true);
            }
            false
        };

        if fs::metadata(&home).is_ok() || remote_exists() {
            return Err(eg!("Another env with the same name exists!"));
        }

        let genesis = if let Some(p) = opts.genesis_tgz_path.as_deref() {
            fs::read(p).c(d!())?
        } else {
            vec![]
        };

        let genesis_vkeys = if let Some(p) = opts.genesis_vkeys_tgz_path.as_deref() {
            fs::read(p).c(d!())?
        } else {
            vec![]
        };

        let mut env = Env {
            meta: EnvMeta {
                name: cfg.name.clone(),
                home,
                hosts: opts.hosts.clone(),
                block_itv: opts.block_itv,
                genesis_pre_settings: opts.genesis_pre_settings.clone(),
                genesis,
                genesis_vkeys,
                genesis_mnemonic_words: Default::default(),
                genesis_validator_num: Default::default(),
                deposit_contract_addr: Default::default(),
                premined_accounts: JsonValue::Null,
                fuhrers: Default::default(),
                nodes: Default::default(),
                nodes_should_be_online: MapxOrd::new(),
                custom_data: opts.custom_data.clone(),
                next_node_id: Default::default(),
            },
            is_protected: true,
            node_cmdline_generator: s,
        };

        fs::create_dir_all(&env.meta.home).c(d!()).and_then(|_| {
            let cmd = format!(
                r#"
                cd {} && \
                git init . && \
                git config user.email x@x.org && \
                git config user.name x
                "#,
                &env.meta.home
            );
            cmd::exec_output(&cmd).c(d!())
        })?;

        // Use chunks to avoid resource overload
        for hosts in env
            .meta
            .hosts
            .as_ref()
            .values()
            .collect::<Vec<_>>()
            .chunks(24)
        {
            let errlist = thread::scope(|s| {
                // collect and iter: let thread::scope finish their work first
                hosts
                    .iter()
                    .map(|h| {
                        let remote = Remote::from(*h);
                        let cmd = format!("mkdir -p {}", &env.meta.home);
                        s.spawn(move || remote.exec_cmd(&cmd).c(d!(&h.meta.addr)))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
                    .map(|e| e.unwrap_err())
                    .collect::<Vec<_>>()
            });

            check_errlist!(@errlist)
        }

        let id = env.next_node_id();
        env.alloc_resources(&[id], NodeKind::Fuhrer, None, None)
            .c(d!())?;

        env.gen_genesis()
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None, false, false).c(d!()))
    }

    // Destroy all nodes
    // - Stop all running processes
    // - Delete the data of every nodes
    fn destroy(&mut self, force: bool) -> Result<()> {
        if !force && self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        info_omit!(self.stop(None, true));
        sleep_ms!(100);

        let mut errlist = vec![];

        // Use chunks to avoid resource overload
        for nodes in self
            .meta
            .fuhrers
            .values()
            .chain(self.meta.nodes.values())
            .collect::<Vec<_>>()
            .chunks(24)
        {
            thread::scope(|s| {
                nodes
                    .iter()
                    .map(|n| s.spawn(|| n.clean_up().c(d!())))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .for_each(|t| {
                        if let Err(e) = t {
                            errlist.push(e);
                        }
                    });
            });
        }

        check_errlist!(@errlist);

        fs::remove_dir_all(&self.meta.home).c(d!())?;

        // Need not do this, for code-readable only.
        errlist.clear();

        // Use chunks to avoid resource overload
        for hosts in self
            .meta
            .hosts
            .as_ref()
            .values()
            .collect::<Vec<_>>()
            .chunks(24)
        {
            thread::scope(|s| {
                hosts
                    .iter()
                    .map(|h| {
                        let remote = Remote::from(*h);
                        let cmd = format!("rm -rf {}", &self.meta.home);
                        s.spawn(move || remote.exec_cmd(&cmd).c(d!(&h.meta.addr)))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .for_each(|t| {
                        if let Err(e) = t {
                            errlist.push(e);
                        }
                    });
            });
        }

        check_errlist!(errlist)
    }

    // Destroy all existing ENVs
    fn destroy_all(force: bool) -> Result<()> {
        for name in Self::get_env_list().c(d!())?.iter() {
            let mut env = Self::load_env_by_name(name)
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

    // Fuhrer nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_nodes(
        &mut self,
        node_kind: NodeKind,
        custom_data: Option<NodeCustomData>,
        host_addr: Option<&HostAddr>,
        num: u8,
    ) -> Result<()> {
        self.push_nodes_data(node_kind, custom_data, host_addr, num)
            .c(d!())
            .and_then(|ids| self.start(Some(ids), false, false).c(d!()))
    }

    fn push_nodes_data(
        &mut self,
        node_kind: NodeKind,
        custom_data: Option<NodeCustomData>,
        host_addr: Option<&HostAddr>,
        num: u8,
    ) -> Result<BTreeSet<NodeID>> {
        let ids = (0..num).map(|_| self.next_node_id()).collect::<Vec<_>>();
        self.alloc_resources(&ids, node_kind, custom_data, host_addr)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(&ids)).c(d!()))
            .map(|_| ids.into_iter().collect())
    }

    // Migrate the target node to another host,
    // NOTE: the node ID will be reallocated
    fn migrate_node(
        &mut self,
        node_id: NodeID,
        new_host_addr: Option<&HostAddr>,
    ) -> Result<NodeID> {
        let old_node = self
            .meta
            .fuhrers
            .get(&node_id)
            .or_else(|| self.meta.nodes.get(&node_id))
            .c(d!("The target node does not exist"))?
            .clone();

        let new_host_addr = if let Some(addr) = new_host_addr {
            addr.clone()
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
                        .map(|h| (h.meta.clone(), (h.node_cnt * max_weight) / h.weight))
                        .collect::<Vec<_>>()
                })?;
            seq.sort_by(|a, b| a.1.cmp(&b.1));
            seq.into_iter()
                .find(|h| h.0.addr != old_node.host.addr)
                .c(d!("no avaliable hosts left, migrate failed"))
                .map(|h| h.0)?
                .addr
        };

        if old_node.host.addr == new_host_addr {
            return Err(eg!("The host where the two nodes are located is the same"));
        }

        let new_node_id = self
            .push_nodes_data(
                old_node.kind,
                old_node.custom_data.clone(),
                Some(&new_host_addr),
                1,
            )
            .c(d!())?
            .into_iter()
            .next()
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
            .and_then(|_| self.kick_node(Some(node_id)).c(d!()))
    }

    // Kick out a target node, or a randomly selected one,
    // NOTE: the fuhrer node will never be kicked
    fn kick_node(&mut self, node_id: Option<NodeID>) -> Result<NodeID> {
        if self.is_protected {
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

        if self.meta.fuhrers.contains_key(&id) {
            return Err(eg!("Node-[{}] is a fuhrer node, deny to kick", id));
        }

        self.meta
            .nodes
            .remove(&id)
            .or_else(|| self.meta.fuhrers.remove(&id))
            .c(d!("Node ID does not exist?"))
            .and_then(|n| {
                self.update_online_status(&[], &[id]);
                self.meta
                    .hosts
                    .as_mut()
                    .get_mut(&n.host.addr.host_id())
                    .unwrap()
                    .node_cnt -= 1;
                n.stop(self, true)
                    .c(d!())
                    .and_then(|_| n.clean_up().c(d!()))
            })
            .and_then(|_| self.write_cfg().c(d!()))
            .map(|_| id)
    }

    fn push_hosts(&mut self, new_hosts: &Hosts) -> Result<()> {
        if self
            .meta
            .hosts
            .as_ref()
            .keys()
            .any(|addr| new_hosts.as_ref().contains_key(addr))
        {
            return Err(eg!("One or more hosts already exist"));
        }
        self.meta.hosts.as_mut().extend(
            new_hosts
                .as_ref()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        self.write_cfg().c(d!())
    }

    fn kick_host(&mut self, host_id: &HostID, force: bool) -> Result<Host> {
        if self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        if let Some(h) = self.meta.hosts.as_ref().get(host_id) {
            if force {
                let mut dup_buf = BTreeSet::new();
                let nodes_to_migrate = self
                    .meta
                    .fuhrers
                    .values()
                    .chain(self.meta.nodes.values())
                    .filter(|n| &n.host.addr.host_id() == host_id)
                    .map(|n| {
                        dup_buf.insert(n.host.addr.clone());
                        n.id
                    })
                    .collect::<BTreeSet<_>>();
                if 2 > dup_buf.len() {
                    return Err(eg!(
                        "Host insufficient(num < 2), add more hosts first!"
                    ));
                }
                for id in nodes_to_migrate.into_iter() {
                    self.migrate_node(id, None).c(d!())?;
                }
            } else if 0 < h.node_cnt {
                return Err(eg!("Some nodes are running on this host!"));
            }

            let removed_host = self.meta.hosts.as_mut().remove(host_id).unwrap();
            self.write_cfg().c(d!()).map(|_| removed_host)
        } else {
            Err(eg!("The target host does not exist!"))
        }
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
    fn start(
        &mut self,
        ids: Option<BTreeSet<NodeID>>,
        ignore_failed: bool,
        realloc_ports: bool,
    ) -> Result<()> {
        let mut nodes = vec![];

        if let Some(ids) = ids {
            for id in ids.iter() {
                if let Some(n) = self
                    .meta
                    .nodes
                    .get_mut(id)
                    .or_else(|| self.meta.fuhrers.get_mut(id))
                {
                    if realloc_ports && !Self::check_node_ports(n).c(d!())? {
                        n.drop_ports();
                        n.ports = Self::alloc_ports(&n.kind, &n.host).c(d!())?;
                    }

                    nodes.push(n.clone());
                } else {
                    return Err(eg!("The node(id: {}) does not exist", id));
                }
            }
        } else {
            for n in self
                .meta
                .fuhrers
                .values_mut()
                .chain(self.meta.nodes.values_mut())
            {
                if realloc_ports && !Self::check_node_ports(n).c(d!())? {
                    n.drop_ports();
                    n.ports = Self::alloc_ports(&n.kind, &n.host).c(d!())?;
                }

                // todo: update ports
                nodes.push(n.clone());
            }
        };

        self.write_cfg().c(d!())?;

        let mut online_ids = vec![];
        let mut errlist = vec![];

        // Use chunks to avoid resource overload
        for (idx, nodes) in nodes.chunks(12).enumerate() {
            thread::scope(|s| {
                nodes
                    .iter()
                    .map(|n| {
                        s.spawn(|| {
                            n.start(self).c(d!()).map(|_| {
                                println!(
                                    "[Chunk {idx}] The node(id: {}) has been started",
                                    n.id
                                );
                                n.id
                            })
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .for_each(|t| match t {
                        Ok(id) => {
                            online_ids.push(id);
                        }
                        Err(e) => {
                            errlist.push(e);
                        }
                    });
            });
        }

        self.update_online_status(&online_ids, &[]);

        if !ignore_failed {
            check_errlist!(@errlist)
        }

        Ok(())
    }

    // Start all existing ENVs
    fn start_all() -> Result<()> {
        for env in Self::get_env_list().c(d!())?.iter() {
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .start(None, false, false)
                .c(d!())?;
        }
        Ok(())
    }

    // - Stop all processes
    // - Release all occupied ports
    fn stop(&mut self, n: Option<&BTreeSet<NodeID>>, force: bool) -> Result<()> {
        let mut errlist = vec![];

        let nodes = if let Some(ids) = n {
            ids.iter()
                .map(|id| {
                    self.meta
                        .nodes
                        .get(id)
                        .or_else(|| self.meta.fuhrers.get(id))
                })
                .rev()
                .collect::<Option<Vec<_>>>()
                .c(d!())?
        } else {
            self.meta
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .collect::<Vec<_>>()
        };

        let mut offline_ids = vec![];
        for (idx, nodes) in nodes.chunks(24).enumerate() {
            thread::scope(|s| {
                nodes
                    .iter()
                    .map(|n| {
                        s.spawn(|| {
                            info!(n.stop(self, force).map(|_| n.id), &n.host.addr)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .for_each(|t| match t {
                        Ok(id) => {
                            offline_ids.push(id);
                            println!(
                                "[Chunk {idx}] The node(id {id}) has been stopped",
                            );
                        }
                        Err(e) => errlist.push(e),
                    });
            });
        }

        self.update_online_status(&[], &offline_ids);
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

    fn debug_failed_nodes(&self) -> Result<()> {
        let (failed_cases, errlist) = self.collect_failed_nodes();
        serde_json::to_string_pretty(&failed_cases)
            .c(d!())
            .map(|s| println!("{s}"))?;
        check_errlist!(errlist)
    }

    #[allow(clippy::type_complexity)]
    pub fn collect_failed_nodes(
        &self,
    ) -> (BTreeMap<HostID, Vec<NodeID>>, Vec<Box<dyn RucError>>) {
        let mut failed_cases = map! {B};
        let mut errlist: Vec<Box<dyn RucError>> = vec![];

        for nodes in self
            .meta
            .nodes
            .values()
            .chain(self.meta.fuhrers.values())
            .collect::<Vec<_>>()
            .chunks(24)
        {
            thread::scope(|s| {
                nodes
                    .iter()
                    .map(|n| {
                        let cmd =
                            self.node_cmdline_generator.cmd_cnt_running(n, &self.meta);
                        s.spawn(move || {
                            let process_cnt = Remote::from(&n.host)
                                .exec_cmd(&cmd)
                                .c(d!())?
                                .trim()
                                .parse::<u64>()
                                .c(d!())?;
                            if 3 > process_cnt {
                                Ok((n, true)) // failed status
                            } else {
                                Ok((n, false)) // well status
                            }
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|hdr| hdr.join())
                    .for_each(|ret| match ret {
                        Ok((n, failed)) => {
                            if failed {
                                failed_cases
                                    .entry(n.host.host_id())
                                    .or_insert_with(Vec::new)
                                    .push(n.id);
                            }
                        }
                        Err(e) => {
                            errlist.push(e);
                        }
                    });
            })
        }

        (failed_cases, errlist)
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

    // 1. Allocate host and ports
    // 2. Create remote home dir
    // 3. Insert new node to the meta of env
    fn alloc_resources(
        &mut self,
        ids: &[NodeID],
        kind: NodeKind,
        custom_data: Option<NodeCustomData>,
        host_addr: Option<&HostAddr>,
    ) -> Result<()> {
        self.alloc_hosts_ports(ids, &kind, host_addr) // 1.
            .c(d!())
            .and_then(|nodes_info| {
                self.apply_resources(&nodes_info, kind, custom_data).c(d!()) // 2.
            })
            .map(|nodes| {
                nodes.into_iter().for_each(|n| match kind {
                    NodeKind::ArchiveNode | NodeKind::FullNode => {
                        self.meta.nodes.insert(n.id, n);
                    }
                    NodeKind::Fuhrer => {
                        self.meta.fuhrers.insert(n.id, n);
                    }
                });
            })
            .and_then(|_| self.write_cfg().c(d!()))
    }

    #[inline(always)]
    fn apply_resources(
        &self,
        nodes_info: &[((NodeID, HostMeta), P)],
        kind: NodeKind,
        custom_data: Option<NodeCustomData>,
    ) -> Result<Vec<Node<P>>> {
        let mut ret = vec![];

        for ni in nodes_info.chunks(24) {
            thread::scope(|s| {
                ni.iter()
                    .cloned()
                    .map(|((id, host), ports)| {
                        let custom_data = custom_data.clone();
                        s.spawn(move || {
                            let home = format!("{}/{}", self.meta.home, id);
                            Remote::from(&host)
                                .exec_cmd(&format!(
                                    "mkdir -p {0} && touch {0}/{MGMT_OPS_LOG}",
                                    &home
                                ))
                                .c(d!())
                                .map(|_| Node {
                                    id,
                                    home,
                                    kind,
                                    custom_data,
                                    host,
                                    ports,
                                })
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|hdr| hdr.join())
                    .collect::<Result<Vec<_>>>()
                    .map(|mut n| ret.append(&mut n))
            })
            .c(d!())?;
        }

        Ok(ret)
    }

    #[inline(always)]
    fn update_online_status(&mut self, nodes_in: &[NodeID], nodes_out: &[NodeID]) {
        nodes_in.iter().copied().for_each(|id| {
            self.meta.nodes_should_be_online.insert(&id, &());
        });

        nodes_out.iter().for_each(|id| {
            self.meta.nodes_should_be_online.remove(id);
        });
    }

    // Allocate unique IDs for nodes within the scope of an env
    #[inline(always)]
    fn next_node_id(&mut self) -> NodeID {
        let ret = self.meta.next_node_id;
        self.meta.next_node_id += 1;
        ret
    }

    // If no genesis data set,
    // build from scratch using [EGG](https://github.com/rust-util-collections/EGG)
    fn gen_genesis(&mut self) -> Result<()> {
        let tmpdir = format!("/tmp/CHAIN_DEV_TMP_{}_{}", ts!(), rand::random::<u16>());
        omit!(fs::remove_dir_all(&tmpdir));
        fs::create_dir_all(&tmpdir).c(d!())?;

        if self.meta.genesis.is_empty() {
            // clone repo
            // custom cfg, eg. block itv
            // build genesis data
            // set generated data to ENV

            let repo = format!("{tmpdir}/egg");
            let cfg = format!("{repo}/custom.env");
            let block_itv_cache = format!("{tmpdir}/block_itv");

            let repo_url = env::var("CHAIN_DEV_EGG_REPO");
            let repo_url = repo_url
                .as_deref()
                .unwrap_or("https://github.com/rust-util-collections/EGG");
            let gitcmd = format!("git clone {repo_url} {repo} || exit 1");
            cmd::exec_output(&gitcmd).c(d!())?;

            if !self.meta.genesis_pre_settings.is_empty() {
                fs::read(&self.meta.genesis_pre_settings)
                    .c(d!())
                    .and_then(|s| fs::write(&cfg, &s).c(d!()))?;
            }

            let cmd = format!(
                r#"
                cd {repo} || exit 1
                if [ ! -f {cfg} ]; then
                    cp {cfg}.example {cfg} || exit 1
                fi
                if [ 0 -lt {0} ]; then
                    sed -i '/SLOT_DURATION_IN_SECONDS/d' {cfg} || exit 1
                    echo 'export SLOT_DURATION_IN_SECONDS="{0}"' >>{cfg} || exit 1
                fi
                grep -Po '(?<= SLOT_DURATION_IN_SECONDS=")\d+' {cfg} >{block_itv_cache} || exit 1
                make minimal_prepare || exit 1
                make build || exit 1
                cp -r {repo}/data/{NODE_HOME_GENESIS_DIR_DST} {1}/ || exit 1
                "#,
                self.meta.block_itv, self.meta.home,
            );

            cmd::exec_output(&cmd).c(d!())?;

            self.meta.block_itv = fs::read_to_string(block_itv_cache)
                .c(d!())
                .and_then(|itv| itv.trim().parse::<BlockItv>().c(d!()))?;

            self.meta.genesis =
                fs::read(format!("{repo}/data/{NODE_HOME_GENESIS_DST}")).c(d!())?;
            self.meta.genesis_vkeys =
                fs::read(format!("{repo}/data/{NODE_HOME_VCDATA_DST}")).c(d!())?;

            let yml =
                format!("{}/{NODE_HOME_GENESIS_DIR_DST}/config.yaml", self.meta.home);
            let ymlhdr = fs::read(&yml)
                .c(d!())
                .and_then(|c| serde_yml::from_slice::<serde_yml::Value>(&c).c(d!()))?;
            self.meta.deposit_contract_addr = ymlhdr["DEPOSIT_CONTRACT_ADDRESS"]
                .as_str()
                .c(d!())?
                .to_owned();

            let yml = format!(
                "{}/{NODE_HOME_GENESIS_DIR_DST}/mnemonics.yaml",
                self.meta.home
            );
            let ymlhdr = fs::read(&yml)
                .c(d!())
                .and_then(|c| serde_yml::from_slice::<serde_yml::Value>(&c).c(d!()))?;
            self.meta.genesis_mnemonic_words =
                ymlhdr[0]["mnemonic"].as_str().unwrap().to_owned();
            self.meta.genesis_validator_num =
                ymlhdr[0]["count"].as_u64().unwrap() as u16;

            let el_genesis_path = format!(
                "{}/{NODE_HOME_GENESIS_DIR_DST}/genesis.json",
                self.meta.home
            );
            self.meta.premined_accounts =
                get_pre_mined_accounts_from_genesis_json(&el_genesis_path).c(d!())?;
        } else {
            if self.meta.genesis_vkeys.is_empty() {
                return Err(eg!(
                    "Validator keys should always be set with the genesis data"
                ));
            }

            // extract the tar.gz,
            // update the `block itv` to the value in the genesis

            let genesis = format!("{tmpdir}/{NODE_HOME_GENESIS_DST}");
            let cmd = format!(
                r#"
                cd {tmpdir} || exit 1
                tar -xpf {genesis} || exit 1
                cp -r {NODE_HOME_GENESIS_DIR_DST} {0}/ || exit 1
                "#,
                self.meta.home
            );
            fs::write(&genesis, &self.meta.genesis)
                .c(d!())
                .and_then(|_| cmd::exec_output(&cmd).c(d!()))?;

            let yml =
                format!("{}/{NODE_HOME_GENESIS_DIR_DST}/config.yaml", self.meta.home);
            let ymlhdr = fs::read(&yml)
                .c(d!())
                .and_then(|c| serde_yml::from_slice::<serde_yml::Value>(&c).c(d!()))?;
            self.meta.block_itv = u16::try_from(max!(
                ymlhdr["SECONDS_PER_SLOT"].as_u64().c(d!())?,
                ymlhdr["SECONDS_PER_ETH1_BLOCK"].as_u64().c(d!())?,
            ))
            .c(d!())?;
            self.meta.deposit_contract_addr = ymlhdr["DEPOSIT_CONTRACT_ADDRESS"]
                .as_str()
                .c(d!())?
                .to_owned();

            let yml = format!(
                "{}/{NODE_HOME_GENESIS_DIR_DST}/mnemonics.yaml",
                self.meta.home
            );
            let ymlhdr = fs::read(&yml)
                .c(d!())
                .and_then(|c| serde_yml::from_slice::<serde_yml::Value>(&c).c(d!()))?;
            self.meta.genesis_mnemonic_words =
                ymlhdr[0]["mnemonic"].as_str().unwrap().to_owned();
            self.meta.genesis_validator_num =
                ymlhdr[0]["count"].as_u64().unwrap() as u16;

            let genesis_json = format!(
                "{}/{NODE_HOME_GENESIS_DIR_DST}/genesis.json",
                self.meta.home
            );
            self.meta.premined_accounts =
                get_pre_mined_accounts_from_genesis_json(&genesis_json).c(d!())?;
        }

        omit!(fs::remove_dir_all(&tmpdir));

        self.write_cfg().c(d!())
    }

    fn apply_genesis(&self, ids: Option<&[NodeID]>) -> Result<()> {
        if self.meta.genesis.is_empty() || self.meta.genesis_vkeys.is_empty() {
            return Err(eg!("BUG: no genesis data"));
        }

        let nodes = if let Some(ids) = ids {
            ids.iter()
                .map(|id| {
                    self.meta
                        .nodes
                        .get(id)
                        .or_else(|| self.meta.fuhrers.get(id))
                })
                .collect::<Option<Vec<_>>>()
                .c(d!())?
        } else {
            self.meta
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .collect()
        };

        let genesis_node_id = *self.meta.fuhrers.first_key_value().c(d!())?.0;

        // Use chunks to avoid resource overload
        for nodes in nodes.chunks(12) {
            let errlist = thread::scope(|s| {
                let mut hdrs = vec![];
                for n in nodes.iter() {
                    let hdr = s.spawn(|| -> Result<()> {
                        let remote = Remote::from(&n.host);
                        let mut p =
                            format!("{}/{NODE_HOME_GENESIS_DST}", n.home.as_str());
                        remote.replace_file(&p, &self.meta.genesis).c(d!())?;
                        if n.id == genesis_node_id {
                            p = format!("{}/{NODE_HOME_VCDATA_DST}", n.home.as_str());
                            remote
                                .replace_file(&p, &self.meta.genesis_vkeys)
                                .c(d!())?;
                        }
                        Ok(())
                    });
                    hdrs.push(hdr);
                }

                hdrs.into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
                    .map(|e| e.unwrap_err())
                    .collect::<Vec<_>>()
            });

            check_errlist!(@errlist)
        }

        Ok(())
    }

    fn load_env_by_cfg<U>(cfg: &EnvCfg<C, P, U>) -> Result<Env<C, P, S>>
    where
        U: CustomOps,
    {
        Self::load_env_by_name(&cfg.name)
            .c(d!(&cfg.name))
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

    // Alloc hosts for new nodes
    fn alloc_hosts_ports(
        &mut self,
        ids: &[NodeID],
        node_kind: &NodeKind,
        host_addr: Option<&HostAddr>,
    ) -> Result<Vec<((NodeID, HostMeta), P)>> {
        let mut hosts = vec![];
        let mut ports = vec![];

        for _ in ids.iter() {
            let h = self.alloc_host(node_kind, host_addr).c(d!())?;
            let p = Self::alloc_ports(node_kind, &h).c(d!())?;
            hosts.push(h);
            ports.push(p);
        }

        Ok(ids.iter().copied().zip(hosts).zip(ports).collect())
    }

    fn alloc_host(
        &mut self,
        node_kind: &NodeKind,
        host_addr: Option<&HostAddr>,
    ) -> Result<HostMeta> {
        if let Some(addr) = host_addr {
            return self
                .meta
                .hosts
                .as_ref()
                .get(&addr.host_id())
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
                .map(|h| (h.meta.clone(), (h.node_cnt * max_weight) / h.weight))
                .collect::<Vec<_>>();
            seq.sort_by(|a, b| a.1.cmp(&b.1));
            seq.into_iter().next().c(d!()).map(|h| h.0)?
        };

        self.meta
            .hosts
            .as_mut()
            .get_mut(&h.addr.host_id())
            .unwrap()
            .node_cnt += 1;

        Ok(h)
    }

    // Return `true` if all existing ports are still ok
    fn check_node_ports(n: &Node<P>) -> Result<bool> {
        let remote = Remote::from(&n.host);

        let host_id = n.host.host_id();

        let occupied = {
            // `cloned`: avoid `dead lock`
            let cache = OCCUPIED_PORTS.read().get(&host_id).cloned();
            if let Some(ports) = cache {
                ports
            } else {
                let ports = remote.get_occupied_ports().c(d!())?;
                OCCUPIED_PORTS.write().insert(host_id, ports.clone());
                ports
            }
        };

        let port_is_free = |p: &u16| !occupied.contains(p);

        Ok(n.ports.get_port_list().iter().all(port_is_free))
    }

    fn alloc_ports(node_kind: &NodeKind, host: &HostMeta) -> Result<P> {
        let reserved_ports = P::reserved();
        let reserved = reserved_ports
            .iter()
            .map(|p| format!("{},{}", &host.addr, p))
            .collect::<Vec<_>>();
        let remote = Remote::from(host);

        let host_id = host.host_id();

        let occupied = {
            // `cloned`: avoid `dead lock`
            let cache = OCCUPIED_PORTS.read().get(&host_id).cloned();
            if let Some(ports) = cache {
                ports
            } else {
                let ports = remote.get_occupied_ports().c(d!())?;
                OCCUPIED_PORTS.write().insert(host_id, ports.clone());
                ports
            }
        };

        let port_is_free = |p: &u16| !occupied.contains(p);

        let mut res = vec![];

        // Avoid the preserved ports to be allocated on any validator node,
        // allow non-valdator nodes(on different hosts) to
        // get the owned preserved ports on their own scopes
        if matches!(node_kind, NodeKind::Fuhrer)
            && reserved.iter().all(|hp| !PC.read().contains(hp))
            && reserved_ports.iter().all(port_is_free)
        {
            res = reserved_ports;
        } else {
            let mut cnter = 5000;
            while reserved.len() > res.len() {
                let p = 10000 + random::<u16>() % (65535 - 21111);
                let hp = format!("{},{}", &host.addr, p);
                if !res.contains(&p)
                    && !reserved_ports.contains(&p)
                    && !PC.read().contains(&hp)
                    && port_is_free(&p)
                {
                    res.push(p);
                }
                cnter -= 1;
                alt!(0 == cnter, return Err(eg!("ports can not be allocated")))
            }
        }

        let mut r = res
            .iter()
            .map(|p| format!("{},{}", &host.addr, p))
            .collect::<Vec<_>>();
        let old_len = r.len();
        r.sort();
        r.dedup();
        assert_eq!(r.len(), old_len);

        PC.write().set(&r);

        P::try_create(&res).c(d!())
    }

    #[inline(always)]
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        EnvMeta::<C, Node<P>>::get_env_list().c(d!())
    }

    #[inline(always)]
    pub fn load_env_by_name(cfg_name: &EnvName) -> Result<Option<Env<C, P, S>>> {
        EnvMeta::<C, Node<P>>::load_env_by_name(cfg_name).c(d!())
    }

    #[inline(always)]
    pub fn hosts_put_file(
        &self,
        local_path: &str,
        remote_path: Option<&str>,
    ) -> Result<()> {
        put_file_to_hosts(&self.meta.hosts, local_path, remote_path).c(d!())
    }

    #[inline(always)]
    pub fn hosts_get_file(
        &self,
        remote_path: &str,
        local_base_dir: Option<&str>,
    ) -> Result<()> {
        get_file_from_hosts(&self.meta.hosts, remote_path, local_base_dir).c(d!())
    }

    #[inline(always)]
    pub fn hosts_exec(
        &self,
        cmd: Option<&str>,
        script_path: Option<&str>,
    ) -> Result<()> {
        exec_cmds_on_hosts(&self.meta.hosts, cmd, script_path).c(d!())
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
        info_omit!(cmd::exec_output(&cmd));

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    pub id: NodeID,
    #[serde(rename = "node_home")]
    pub home: String,
    pub host: HostMeta,
    pub ports: P,
    pub kind: NodeKind,

    // custom data set by USER
    pub custom_data: Option<NodeCustomData>,
}

impl<P: NodePorts> Node<P> {
    fn start<C, S>(&self, env: &Env<C, P, S>) -> Result<()>
    where
        C: CustomData,
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
        C: CustomData,
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
        let logfile = format!("{}/{MGMT_OPS_LOG}", &self.home);
        Remote::from(&self.host)
            .append_file(logfile, log.as_bytes())
            .c(d!())
    }

    // - Release all occupied ports
    // - Remove all files related to this node
    #[inline(always)]
    fn clean_up(&self) -> Result<()> {
        self.drop_ports();

        // Remove all related files
        Remote::from(&self.host)
            .exec_cmd(&format!("rm -rf {}", &self.home))
            .c(d!())
            .map(|_| ())
    }

    #[inline(always)]
    fn drop_ports(&self) {
        for port in self.ports.get_port_list().iter() {
            PC.write().remove(&format!("{},{}", &self.host.addr, port));
        }
    }

    // Migrate this node to another host,
    // NOTE: the node ID has been changed
    fn migrate<C, S>(&self, new_node: &Node<P>, env: &Env<C, P, S>) -> Result<()>
    where
        C: CustomData,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<C, P, U>
where
    C: CustomData,
    P: NodePorts,
    U: CustomOps,
{
    Create {
        opts: EnvOpts<C>,
    },
    Destroy {
        force: bool,
    },
    DestroyAll {
        force: bool,
    },
    PushNodes {
        host: Option<HostAddr>,
        custom_data: NodeCustomData,
        fullnode: bool, /*for archive node set `false`*/
        num: u8,        /*how many new nodes to add*/
    },
    MigrateNodes {
        nodes: BTreeSet<NodeID>,
        host: Option<HostAddr>, /*if not set, will select another host from the existing ones*/
    },
    KickNodes {
        nodes: Option<BTreeSet<NodeID>>,
        num: u8, /*how many nodes to kick if no specific ids are specified*/
    },
    PushHosts {
        hosts: Hosts,
    },
    KickHosts {
        hosts: Vec<HostID>,
        force: bool,
    },
    Protect,
    Unprotect,
    Start {
        nodes: Option<BTreeSet<NodeID>>,
        ignore_failed: bool, /*ignore failed cases or not*/
        realloc_ports: bool, /*try to realloc ports or not*/
    },
    StartAll,
    Stop {
        nodes: Option<BTreeSet<NodeID>>,
        force: bool, /*force(kill -9) or not*/
    },
    StopAll {
        force: bool,
    },
    DebugFailedNodes,
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
pub struct EnvOpts<C: CustomData> {
    /// The host list of the env
    pub hosts: Hosts,

    /// Seconds between two blocks, aka BlockTime
    pub block_itv: BlockItv,

    /// The contents of a EGG custom.env,
    ///
    /// Format:
    /// - https://github.com/rust-util-collections/EGG/blob/master/custom.env.example
    pub genesis_pre_settings: String,

    /// The network cfg files,
    /// a gzip compressed tar package
    pub genesis_tgz_path: Option<String>,

    /// The initial validator keys,
    /// a gzip compressed tar package
    pub genesis_vkeys_tgz_path: Option<String>,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: C,

    /// Try to destroy env with the same name,
    /// and create a new one
    pub force_create: bool,
}

static PC: LazyLock<RwLock<PortsCache>> =
    LazyLock::new(|| RwLock::new(pnk!(PortsCache::load_or_create())));

#[derive(Serialize, Deserialize)]
struct PortsCache {
    // [ <remote addr + remote port> ]
    port_set: MapxOrd<String, ()>,
}

impl PortsCache {
    fn load_or_create() -> Result<Self> {
        let dir = format!("{}/ports_cache", &*GLOBAL_BASE_DIR);
        fs::create_dir_all(&dir).c(d!())?;

        let meta_path = format!("{}/meta.json", &dir);

        let ret = match fs::read(&meta_path) {
            Ok(c) => serde_json::from_slice(&c).c(d!())?,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    let r = Self {
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

    fn set(&mut self, ports: &[String]) {
        for p in ports {
            let v = self.port_set.insert(&p.to_owned(), &());
            assert!(v.is_none(), "{}", p);
        }
    }

    fn remove(&self, port: &str) {
        unsafe { self.port_set.shadow() }.remove(&port.to_owned());
    }
}
