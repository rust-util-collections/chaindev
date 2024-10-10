//!
//! Distributed version
//!

pub mod host;
pub mod remote;

use crate::check_errlist;
use host::HostMeta;
use rand::random;
use remote::Remote;
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
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
            Op::PushNode((host_addr, node_mark, fullnode)) => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        env.push_node(
                            alt!(*fullnode, NodeKind::FullNode, NodeKind::ArchiveNode,),
                            Some(*node_mark),
                            host_addr.as_ref(),
                        )
                        .c(d!())
                    })
            }
            Op::MigrateNode((node_id, host_addr)) => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        env.migrate_node(*node_id, host_addr.as_ref()).c(d!())
                    })
            }
            Op::KickNode(node_id) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node(*node_id).c(d!())),
            Op::PushHost(hosts) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_host(hosts).c(d!())),
            Op::KickHost((host_id, force)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_host(host_id, *force).c(d!())),
            Op::Protect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start(node_id) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.start(*node_id).c(d!())),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop((node_id, force)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.stop(*node_id, *force).c(d!())),
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
    #[serde(rename = "home_dir")]
    pub home: String,

    #[serde(rename = "remote_hosts")]
    pub hosts: Hosts,

    /// Seconds between two blocks
    #[serde(rename = "block_time_in_seconds")]
    pub block_itv: BlockItv,

    /// The contents of a EGG custom.env,
    ///
    /// Format:
    /// - https://github.com/NBnet/EGG/blob/master/custom.env.example
    pub genesis_pre_settings: String,

    /// The network cfg files,
    /// a gzip compressed tar package
    pub genesis: Vec<u8>,

    /// The initial validator keys,
    /// a gzip compressed tar package
    pub genesis_vkeys: Vec<u8>,

    /// The first Bootstrap node
    /// will be treated as the genesis node
    #[serde(rename = "bootstrap_nodes")]
    pub bootstraps: BTreeMap<NodeID, N>,

    /// Non-bootstrap node collection
    pub nodes: BTreeMap<NodeID, N>,

    /// An in-memory cache for recording node status,
    pub nodes_should_be_online: MapxOrd<NodeID, ()>,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: C,

    /// Node ID allocator
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
        let node = self.bootstraps.values().chain(self.nodes.values()).next();
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
                            info!(remote.exec_cmd(&cmd), &h.meta.addr)
                        })
                    })
                    .collect::<Vec<_>>();
                let errlist = hdrs
                    .into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
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
                bootstraps: Default::default(),
                nodes: Default::default(),
                nodes_should_be_online: MapxOrd::new(),
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
                .collect::<Vec<_>>();
            check_errlist!(errlist)
        })?;

        macro_rules! add_initial_nodes {
            ($kind: expr) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, $kind, None, None).c(d!())?;
            }};
        }

        add_initial_nodes!(NodeKind::Bootstrap);
        for _ in 0..opts.initial_node_num {
            add_initial_nodes!(alt!(
                opts.initial_nodes_fullnode,
                NodeKind::FullNode,
                NodeKind::ArchiveNode,
            ));
        }

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

        let errlist = thread::scope(|s| {
            let hdrs = self
                .meta
                .bootstraps
                .values()
                .chain(self.meta.nodes.values())
                .map(|n| s.spawn(|| n.clean_up().c(d!())))
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
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
                    let remote = Remote::from(h);
                    let cmd = format!("rm -rf {}", &self.meta.home);
                    s.spawn(move || info!(remote.exec_cmd(&cmd), &h.meta.addr))
                })
                .collect::<Vec<_>>();
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

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

    // Bootstrap nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(
        &mut self,
        node_kind: NodeKind,
        node_mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
    ) -> Result<()> {
        self.push_node_data(node_kind, node_mark, host_addr)
            .c(d!())
            .and_then(|id| self.start(Some(id)).c(d!()))
    }

    fn push_node_data(
        &mut self,
        node_kind: NodeKind,
        node_mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
    ) -> Result<NodeID> {
        let id = self.next_node_id();
        self.alloc_resources(id, node_kind, node_mark, host_addr)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .map(|_| id)
    }

    // Migrate the target node to another host,
    // NOTE: the node ID will be reallocated
    fn migrate_node(
        &mut self,
        node_id: NodeID,
        new_host_addr: Option<&HostAddr>,
    ) -> Result<()> {
        let old_node = self
            .meta
            .bootstraps
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
            .push_node_data(old_node.kind, old_node.mark, Some(&new_host_addr))
            .c(d!())?;
        let new_node = self
            .meta
            .bootstraps
            .get(&new_node_id)
            .or_else(|| self.meta.nodes.get(&new_node_id))
            .c(d!("BUG"))?;

        old_node
            .migrate(new_node, self)
            .c(d!())
            .and_then(|_| self.kick_node(Some(node_id)).c(d!()))
    }

    // Kick out a target node, or a randomly selected one,
    // NOTE: the bootstrap node will never be kicked
    fn kick_node(&mut self, node_id: Option<NodeID>) -> Result<()> {
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
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .next_back()
                .c(d!("no node found"))?
        };

        self.update_online_status(&[], &[id]);

        self.meta
            .nodes
            .remove(&id)
            .or_else(|| self.meta.bootstraps.remove(&id))
            .c(d!("Node ID does not exist?"))
            .and_then(|n| {
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
    }

    fn push_host(&mut self, new_hosts: &Hosts) -> Result<()> {
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

    fn kick_host(&mut self, host_id: &HostID, force: bool) -> Result<()> {
        if self.is_protected {
            return Err(eg!(
                "This env({}) is protected, `unprotect` it first",
                self.meta.name
            ));
        }

        if force {
            let mut dup_buf = BTreeSet::new();
            let nodes_to_migrate = self
                .meta
                .bootstraps
                .values()
                .chain(self.meta.nodes.values())
                .filter(|n| &n.host.addr.host_id() == host_id)
                .map(|n| {
                    dup_buf.insert(n.host.addr.clone());
                    n.id
                })
                .collect::<BTreeSet<_>>();
            if 2 > dup_buf.len() {
                return Err(eg!("Host insufficient(num < 2), add more hosts first!"));
            }
            for id in nodes_to_migrate.into_iter() {
                self.migrate_node(id, None).c(d!())?;
            }
        } else if let Some(n) =
            self.meta.hosts.as_ref().get(host_id).map(|h| h.node_cnt)
        {
            if 0 < n {
                return Err(eg!("Some nodes are running on this host!"));
            }
        } else {
            return Err(eg!("The target host does not exist!"));
        }

        self.meta.hosts.as_mut().remove(host_id);
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
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_online_status(&ids, &[]);

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for i in ids.iter() {
                let hdr = s.spawn(|| {
                    if let Some(n) = self
                        .meta
                        .bootstraps
                        .get(i)
                        .or_else(|| self.meta.nodes.get(i))
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
    fn stop(&mut self, n: Option<NodeID>, force: bool) -> Result<()> {
        if let Some(id) = n {
            if let Some(n) = self
                .meta
                .nodes
                .get(&id)
                .or_else(|| self.meta.bootstraps.get(&id))
            {
                n.stop(self, force)
                    .c(d!(&n.host.addr))
                    .map(|_| self.update_online_status(&[], &[id]))
            } else {
                Err(eg!("The target node not found"))
            }
        } else {
            // Need NOT to call the `update_online_status`
            // for an entire stopped ENV, meaningless
            let errlist = thread::scope(|s| {
                let hdrs = self
                    .meta
                    .bootstraps
                    .values()
                    .chain(self.meta.nodes.values())
                    .map(|n| s.spawn(|| info!(n.stop(self, force), &n.host.addr)))
                    .collect::<Vec<_>>();
                hdrs.into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
                    .collect::<Vec<_>>()
            });

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

    #[inline(always)]
    fn show(&self) {
        let mut ret = pnk!(serde_json::to_value(self));

        // Clean unreadable fields
        ret["meta"].as_object_mut().unwrap().remove("genesis");
        ret["meta"].as_object_mut().unwrap().remove("genesis_vkeys");
        ret["meta"]
            .as_object_mut()
            .unwrap()
            .remove("nodes_should_be_online");

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
        id: NodeID,
        kind: NodeKind,
        mark: Option<NodeMark>,
        host_addr: Option<&HostAddr>,
    ) -> Result<()> {
        self.alloc_hosts_ports(&kind, host_addr) // 1.
            .c(d!())
            .and_then(|(host, ports)| {
                self.apply_resources(id, kind, mark, host, ports).c(d!()) // 2.
            })
            .map(|node| {
                match kind {
                    NodeKind::FullNode | NodeKind::ArchiveNode => {
                        self.meta.nodes.insert(id, node)
                    }
                    NodeKind::Bootstrap => self.meta.bootstraps.insert(id, node),
                };
            })
            .and_then(|_| self.write_cfg().c(d!()))
    }

    #[inline(always)]
    fn apply_resources(
        &self,
        id: NodeID,
        kind: NodeKind,
        mark: Option<NodeMark>,
        host: HostMeta,
        ports: P,
    ) -> Result<Node<P>> {
        let home = format!("{}/{}", self.meta.home, id);
        Remote::from(&host)
            .exec_cmd(&format!("mkdir -p {}", &home))
            .c(d!())
            .map(|_| Node {
                id,
                home,
                kind,
                mark,
                host,
                ports,
            })
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
    // build from scratch using [EGG](https://github.com/NBnet/EGG)
    fn gen_genesis(&mut self) -> Result<()> {
        let tmpdir = format!("/tmp/egg_{}_{}", ts!(), rand::random::<u16>());
        omit!(fs::remove_dir_all(&tmpdir));
        fs::create_dir_all(&tmpdir).c(d!())?;

        if self.meta.genesis.is_empty() {
            // clone repo
            // custom cfg, eg. block itv
            // build genesis data
            // set generated data to ENV

            let repo = format!("{tmpdir}/egg");
            let cfg = format!("{repo}/custom.env");

            let gitcmd =
                format!("git clone https://gitee.com/kt10/EGG.git {repo} || exit 1");
            let gitcmd2 =
                format!("git clone https://github.com/NBnet/EGG {repo} || exit 1");
            cmd::exec_output(&gitcmd)
                .c(d!())
                .or_else(|_| cmd::exec_output(&gitcmd2).c(d!()))?;

            if !self.meta.genesis_pre_settings.is_empty() {
                fs::write(&cfg, self.meta.genesis_pre_settings.as_bytes()).c(d!())?;
            }

            let cmd = format!(
                r#"
                cd {repo} || exit 1
                if [ ! -f {cfg} ]; then
                    cp {cfg}.example {cfg} || exit 1
                fi
                if [ 0 -lt {0} ]; then
                    sed -i '/SLOT_DURATION_IN_SECONDS/d' {cfg} || exit 1
                    echo 'export SLOT_DURATION_IN_SECONDS="{0}"' >>${cfg} || exit 1
                fi
                make minimal_prepare || exit 1
                make build
                "#,
                self.meta.block_itv
            );

            cmd::exec_output(&cmd).c(d!())?;

            self.meta.genesis =
                fs::read(format!("{repo}/data/{NODE_HOME_GENESIS_DST}")).c(d!())?;
            self.meta.genesis_vkeys =
                fs::read(format!("{repo}/data/{NODE_HOME_VCDATA_DST}")).c(d!())?;
        } else {
            if self.meta.genesis_vkeys.is_empty() {
                return Err(eg!(
                    "Validator keys should always be set with the genesis data"
                ));
            }

            // extract the tar.gz,
            // update the `block itv` to the value in the genesis

            let genesis = format!("{tmpdir}/{NODE_HOME_GENESIS_DST}");
            let yml = format!("{tmpdir}/config.yaml");
            let cmd = format!("tar -xpf {genesis} && cp ${tmpdir}/*/config.yaml {yml}");
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
        }

        omit!(fs::remove_dir_all(&tmpdir));

        self.write_cfg().c(d!())
    }

    fn apply_genesis(&self, id: Option<NodeID>) -> Result<()> {
        if self.meta.genesis.is_empty() || self.meta.genesis_vkeys.is_empty() {
            return Err(eg!("BUG: no genesis data"));
        }

        let nodes = if let Some(id) = id {
            self.meta
                .nodes
                .get(&id)
                .or_else(|| self.meta.bootstraps.get(&id))
                .c(d!())
                .map(|n| vec![n])?
        } else {
            self.meta
                .bootstraps
                .values()
                .chain(self.meta.nodes.values())
                .collect()
        };

        let genesis_node_id = *self.meta.bootstraps.keys().next().c(d!())?;

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for n in nodes.iter() {
                let hdr = s.spawn(|| -> Result<()> {
                    let remote = Remote::from(&n.host);
                    let mut p = format!("{}/{NODE_HOME_GENESIS_DST}", n.home.as_str());
                    remote.write_append_file(&p, &self.meta.genesis).c(d!())?;
                    if n.id == genesis_node_id {
                        p = format!("{}/{NODE_HOME_VCDATA_DST}", n.home.as_str());
                        remote
                            .write_append_file(&p, &self.meta.genesis_vkeys)
                            .c(d!())?;
                    }
                    Ok(())
                });
                hdrs.push(hdr);
            }

            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
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
        node_kind: &NodeKind,
        host_addr: Option<&HostAddr>,
    ) -> Result<(HostMeta, P)> {
        let host = self.alloc_host(node_kind, host_addr).c(d!())?;
        let ports = self.alloc_ports(node_kind, &host).c(d!())?;
        Ok((host, ports))
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

        let h = if matches!(node_kind, NodeKind::Bootstrap) {
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
        let reserved_ports = P::reserved();
        let reserved = reserved_ports
            .iter()
            .map(|p| format!("{},{}", &host.addr, p))
            .collect::<Vec<_>>();
        let remote = Remote::from(host);

        let occupied = remote.get_occupied_ports().c(d!())?;
        let port_is_free = |p: &u16| !occupied.contains(p);

        let mut res = vec![];

        // Avoid the preserved ports to be allocated on any validator node,
        // allow non-valdator nodes(on different hosts) to
        // get the owned preserved ports on their own scopes
        if matches!(node_kind, NodeKind::Bootstrap)
            && ENV_NAME_DEFAULT == self.meta.name.as_ref()
            && reserved.iter().all(|hp| !PC.contains(hp))
            && reserved_ports.iter().all(port_is_free)
        {
            res = reserved_ports;
        } else {
            let mut cnter = 10000;
            while reserved.len() > res.len() {
                let p = 20000 + random::<u16>() % (65535 - 20000);
                let hp = format!("{},{}", &host.addr, p);
                if !reserved.contains(&hp) && !PC.contains(&hp) && port_is_free(&p) {
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
    #[serde(rename = "home_dir")]
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
            return Err(eg!("This node({}, {}) is running ...", self.id, self.home));
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
            .write_append_file(logfile, log.as_bytes())
            .c(d!())
    }

    // - Release all occupied ports
    // - Remove all files related to this node
    fn clean_up(&self) -> Result<()> {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<C, P, U>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create(EnvOpts<C>),
    Destroy(bool),                                // force or not
    DestroyAll(bool),                             // force or not
    PushNode((Option<HostAddr>, NodeMark, bool)), // for full node, set `true`; archive node set `false`
    MigrateNode((NodeID, Option<HostAddr>)),
    KickNode(Option<NodeID>),
    PushHost(Hosts),
    KickHost((HostID, bool)), // force or not
    Protect,
    Unprotect,
    Start(Option<NodeID>),
    StartAll,
    Stop((Option<NodeID>, bool)), // force or not
    StopAll(bool),                // force or not
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
    /// - https://github.com/NBnet/EGG/blob/master/custom.env.example
    pub genesis_pre_settings: String,

    /// The network cfg files,
    /// a gzip compressed tar package
    pub genesis_tgz_path: Option<String>,

    /// The initial validator keys,
    /// a gzip compressed tar package
    pub genesis_vkeys_tgz_path: Option<String>,

    /// How many initial nodes should be created,
    /// including the bootstrap node
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

static PC: LazyLock<PortsCache> = LazyLock::new(|| pnk!(PortsCache::load_or_create()));

#[derive(Serialize, Deserialize)]
struct PortsCache {
    dir: String,
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
                        dir,
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
