//!
//! Distributed version
//!

pub mod host;
pub mod remote;

use crate::check_errlist;
use host::HostMeta;
use parking_lot::RwLock;
use rand::random;
use remote::Remote;
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
pub use host::{Host, HostAddr, HostExpression, HostExpressionRef, HostID, Hosts};

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__D_DEV__", &*BASE_DIR));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<C, P, U>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    pub fn exec<S>(&self, s: S) -> Result<()>
    where
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        match &self.op {
            Op::Create(envopts) => Env::<C, P, S>::create(self, envopts, s).c(d!()),
            Op::Destroy(force) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.destroy(*force).c(d!())),
            Op::DestroyAll(force) => Env::<C, P, S>::destroy_all(*force).c(d!()),
            Op::PushNodes((host_addr, node_mark, fullnode, num)) => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        env.push_nodes(
                            alt!(*fullnode, NodeKind::FullNode, NodeKind::ArchiveNode,),
                            Some(*node_mark),
                            host_addr.as_ref(),
                            *num,
                        )
                        .c(d!())
                    })
            }
            Op::MigrateNodes((node_ids, host_addr)) => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        // `rev()`: migrate newer nodes(bigger id) at first
                        for (i, id) in node_ids.iter().rev().enumerate() {
                            env.migrate_node(*id, host_addr.as_ref()).c(d!())?;
                            println!(
                                "The {}th node has been migrated, NodeID: {id}",
                                1 + i
                            );
                        }
                        Ok(())
                    })
            }
            Op::KickNodes((node_ids, num)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = node_ids {
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
            Op::PushHosts(hosts) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_hosts(hosts).c(d!())),
            Op::KickHosts((host_ids, force)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    for (i, id) in host_ids.iter().enumerate() {
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
            Op::Start(node_ids) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = node_ids {
                        for (i, id) in ids.iter().copied().enumerate() {
                            env.start(Some(vec![id])).c(d!())?;
                            println!(
                                "The {}th node has been started, NodeID: {id}",
                                1 + i
                            );
                        }
                        Ok(())
                    } else {
                        env.start(None).c(d!())
                    }
                }),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop((node_ids, force)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = node_ids {
                        env.stop(Some(ids), *force).c(d!())
                    } else {
                        env.stop(None, *force).c(d!())
                    }
                }),
            Op::StopAll(force) => Env::<C, P, S>::stop_all(*force).c(d!()),
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
                    remote::put_file_to_hosts(
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
                    remote::get_file_from_hosts(
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
                    remote::exec_cmds_on_hosts(
                        hosts,
                        cmd.as_deref(),
                        script_path.as_deref(),
                    )
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

        fs::create_dir_all(&env.meta.home).c(d!())?;

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
                        let cmd = format!("mkdir -p {}", &env.meta.home);
                        s.spawn(move || {
                            let remote = Remote::from(*h);
                            info!(remote.exec_cmd(&cmd), &h.meta.addr)
                        })
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

        macro_rules! add_initial_nodes {
            ($ids: expr, $kind: expr) => {{
                env.alloc_resources($ids, $kind, None, None).c(d!())?;
            }};
        }

        let id = env.next_node_id();
        add_initial_nodes!(&[id], NodeKind::Fuhrer);

        let ids = (0..opts.initial_node_num)
            .map(|_| env.next_node_id())
            .collect::<Vec<_>>();
        add_initial_nodes!(
            &ids,
            alt!(
                opts.initial_nodes_fullnode,
                NodeKind::FullNode,
                NodeKind::ArchiveNode,
            )
        );

        env.gen_genesis()
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None).c(d!()))
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
                        s.spawn(move || info!(remote.exec_cmd(&cmd), &h.meta.addr))
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
        node_mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
        num: u8,
    ) -> Result<()> {
        self.push_nodes_data(node_kind, node_mark, host_addr, num)
            .c(d!())
            .and_then(|ids| self.start(Some(ids)).c(d!()))
    }

    fn push_nodes_data(
        &mut self,
        node_kind: NodeKind,
        node_mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
        num: u8,
    ) -> Result<Vec<NodeID>> {
        let ids = (0..num).map(|_| self.next_node_id()).collect::<Vec<_>>();
        self.alloc_resources(&ids, node_kind, node_mark, host_addr)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(&ids)).c(d!()))
            .map(|_| ids)
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
            .push_nodes_data(old_node.kind, old_node.mark, Some(&new_host_addr), 1)
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
            return Err(eg!("Node-[{id}] is a fuhrer node, deny to kick"));
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
    fn start(&mut self, n: Option<Vec<NodeID>>) -> Result<()> {
        let ids = n
            .map(|mut ids| {
                ids.sort();
                ids.dedup();
                ids
            })
            .unwrap_or_else(|| {
                self.meta
                    .fuhrers
                    .keys()
                    .chain(self.meta.nodes.keys())
                    .copied()
                    .collect()
            });

        self.update_online_status(&ids, &[]);

        // Use chunks to avoid resource overload
        for (idx, ids) in ids.chunks(12).enumerate() {
            let errlist = thread::scope(|s| {
                let mut hdrs = vec![];
                for id in ids.iter() {
                    let hdr = s.spawn(|| {
                        if let Some(n) = self
                            .meta
                            .fuhrers
                            .get(id)
                            .or_else(|| self.meta.nodes.get(id))
                        {
                            n.start(self).c(d!()).map(|_| {
                                println!(
                                    "[Chunk {idx}] The node(id: {}) has been started",
                                    *id
                                );
                            })
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
                .start(None)
                .c(d!())?;
        }
        Ok(())
    }

    // - Stop all processes
    // - Release all occupied ports
    fn stop(&mut self, n: Option<&BTreeSet<NodeID>>, force: bool) -> Result<()> {
        let mut errlist = vec![];

        if let Some(ids) = n {
            let nodes = ids
                .iter()
                .map(|id| {
                    self.meta
                        .nodes
                        .get(id)
                        .or_else(|| self.meta.fuhrers.get(id))
                        .cloned()
                })
                .rev()
                .collect::<Option<Vec<_>>>()
                .c(d!())?;

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
                        .collect::<Vec<_>>()
                })
                .into_iter()
                .for_each(|t| match t {
                    Ok(id) => {
                        self.update_online_status(&[], &[id]);
                        println!("[Chunk {idx}] The node(id {id}) has been stopped",);
                    }
                    Err(e) => errlist.push(e),
                });
            }

            check_errlist!(errlist)
        } else {
            // Need NOT to call the `update_online_status`
            // for an entire stopped ENV, meaningless

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
                        .map(|n| s.spawn(|| info!(n.stop(self, force), &n.host.addr)))
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

    // Clean unreadable fields,
    // make low-readable fields clear
    #[inline(always)]
    fn show(&self) {
        let mut ret = pnk!(serde_json::to_value(self));

        ret.as_object_mut()
            .unwrap()
            .remove("node_cmdline_generator");

        let meta = ret["meta"].as_object_mut().unwrap();

        for i in ["nodes", "fuhrer_nodes"] {
            for n in meta[i].as_object_mut().unwrap().values_mut() {
                let n = n.as_object_mut().unwrap();
                let mark = n.remove("mark").unwrap();
                let mark = alt!(mark.as_null().is_some(), 0, mark.as_u64().unwrap());
                n.insert("el_type".to_owned(), alt!(0 == mark, "geth", "reth").into());
                n.insert("cl_type".to_owned(), "lighthouse".into());
            }
        }

        meta.remove("genesis");
        meta.remove("genesis_vkeys");
        meta.remove("nodes_should_be_online");
        meta.remove("next_node_id");

        let mut hosts = meta.remove("remote_hosts").unwrap();
        meta.insert(
            "remote_hosts".to_string(),
            hosts
                .as_object_mut()
                .unwrap()
                .values_mut()
                .map(|v| v.take())
                .collect::<Vec<_>>()
                .into(),
        );

        println!("{}", pnk!(serde_json::to_string_pretty(&ret)));
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

    // 1. Allocate host and ports
    // 2. Create remote home dir
    // 3. Insert new node to the meta of env
    fn alloc_resources(
        &mut self,
        ids: &[NodeID],
        kind: NodeKind,
        mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
    ) -> Result<()> {
        self.alloc_hosts_ports(ids, &kind, host_addr) // 1.
            .c(d!())
            .and_then(|nodes_info| {
                self.apply_resources(&nodes_info, kind, mark).c(d!()) // 2.
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
        nodes_info: &[(NodeID, HostMeta, P)],
        kind: NodeKind,
        mark: Option<NodeMark>,
    ) -> Result<Vec<Node<P>>> {
        let mut ret = vec![];

        for ni in nodes_info.chunks(24) {
            thread::scope(|s| {
                ni.iter()
                    .cloned()
                    .map(|(id, host, ports)| {
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
                                    mark,
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
                make build
                "#,
                self.meta.block_itv
            );

            cmd::exec_output(&cmd).c(d!())?;

            self.meta.block_itv = fs::read_to_string(block_itv_cache)
                .c(d!())
                .and_then(|itv| itv.trim().parse::<BlockItv>().c(d!()))?;

            self.meta.genesis =
                fs::read(format!("{repo}/data/{NODE_HOME_GENESIS_DST}")).c(d!())?;
            self.meta.genesis_vkeys =
                fs::read(format!("{repo}/data/{NODE_HOME_VCDATA_DST}")).c(d!())?;

            let el_genesis_path = format!("{repo}/data/genesis/genesis.json");
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
            let cmd = format!("tar -C {tmpdir} -xpf {genesis} && cp {tmpdir}/*/{{config.yaml,genesis.json}} /{tmpdir}/");

            let yml = format!("{tmpdir}/config.yaml");
            let genesis_json = format!("{tmpdir}/genesis.json");

            fs::write(&genesis, &self.meta.genesis)
                .c(d!())
                .and_then(|_| cmd::exec_output(&cmd).c(d!()))?;

            let ymlhdr = fs::read(&yml)
                .c(d!())
                .and_then(|c| serde_yml::from_slice::<serde_yml::Value>(&c).c(d!()))?;

            self.meta.block_itv = u16::try_from(max!(
                ymlhdr["SECONDS_PER_SLOT"].as_u64().c(d!())?,
                ymlhdr["SECONDS_PER_ETH1_BLOCK"].as_u64().c(d!())?,
            ))
            .c(d!())?;

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

    // Alloc <host,ports> for a new node
    fn alloc_hosts_ports(
        &mut self,
        ids: &[NodeID],
        node_kind: &NodeKind,
        host_addr: Option<&HostAddr>,
    ) -> Result<Vec<(NodeID, HostMeta, P)>> {
        let mut hosts = vec![];
        for _ in ids.iter() {
            hosts.push(self.alloc_host(node_kind, host_addr).c(d!())?);
        }

        let ports = hosts
            .iter()
            .map(|h| self.alloc_ports(node_kind, h).c(d!()))
            .collect::<Result<Vec<_>>>()?;

        Ok(ids
            .iter()
            .copied()
            .zip(hosts)
            .zip(ports)
            .map(|((id, host), ports)| (id, host, ports))
            .collect())
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

    fn alloc_ports(&self, node_kind: &NodeKind, host: &HostMeta) -> Result<P> {
        static OCCUPIED_PORTS: LazyLock<RwLock<BTreeMap<HostID, BTreeSet<u16>>>> =
            LazyLock::new(|| RwLock::new(BTreeMap::new()));

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
            && ENV_NAME_DEFAULT == self.meta.name.as_ref()
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
        remote::put_file_to_hosts(&self.meta.hosts, local_path, remote_path).c(d!())
    }

    #[inline(always)]
    pub fn hosts_get_file(
        &self,
        remote_path: &str,
        local_base_dir: Option<&str>,
    ) -> Result<()> {
        remote::get_file_from_hosts(&self.meta.hosts, remote_path, local_base_dir)
            .c(d!())
    }

    #[inline(always)]
    pub fn hosts_exec(
        &self,
        cmd: Option<&str>,
        script_path: Option<&str>,
    ) -> Result<()> {
        remote::exec_cmds_on_hosts(&self.meta.hosts, cmd, script_path).c(d!())
    }

    #[inline(always)]
    pub fn write_cfg(&self) -> Result<()> {
        serde_json::to_vec(self)
            .c(d!())
            .and_then(|d| fs::write(format!("{}/CONFIG", &self.meta.home), d).c(d!()))
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
    pub mark: Option<NodeMark>, // custom mark set by USER
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
                    "This node({}, {}) may be running, {} processes detected.",
                    self.id,
                    self.home,
                    process_cnt
                ));
            } else {
                println!(
                    "This node({}, {}) may be in a partial failed state,
                less than {} live processes detected, enter the restart process.",
                    self.id, self.home, process_cnt
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
        let logfile = format!("{}/{MGMT_OPS_LOG}", &self.home);
        Remote::from(&self.host)
            .append_file(logfile, log.as_bytes())
            .c(d!())
    }

    // - Release all occupied ports
    // - Remove all files related to this node
    fn clean_up(&self) -> Result<()> {
        for port in self.ports.get_port_list().iter() {
            PC.write().remove(&format!("{},{}", &self.host.addr, port));
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<C, P, U>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create(EnvOpts<C>),
    Destroy(bool),    // force or not
    DestroyAll(bool), // force or not
    PushNodes(
        (
            Option<HostAddr>,
            NodeMark,
            bool, /*for full node, set `true`; archive node set `false`*/
            u8,   /*how many new nodes to add*/
        ),
    ),
    MigrateNodes(
        (
            BTreeSet<NodeID>,
            Option<HostAddr>, /*if not set, will select another host from the existing ones*/
        ),
    ),
    KickNodes(
        (
            Option<BTreeSet<NodeID>>,
            u8, /*how many nodes to kick if no specific ids are specified*/
        ),
    ),
    PushHosts(Hosts),
    KickHosts((Vec<HostID>, bool /*force or not*/)),
    Protect,
    Unprotect,
    Start(Option<BTreeSet<NodeID>>),
    StartAll,
    Stop(
        (
            Option<BTreeSet<NodeID>>,
            bool, /*force(kill -9) or not*/
        ),
    ),
    StopAll(bool /*force or not*/),
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
pub struct EnvOpts<C>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
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

    /// How many initial nodes should be created,
    /// including the fuhrer node
    pub initial_node_num: u8,

    /// Set nodes as ArchiveNode by default
    pub initial_nodes_fullnode: bool,

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
