//!
//! Localhost version
//!

#![allow(warnings)]

use nix::{
    sys::socket::{
        self, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, SockaddrIn,
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
    process::{exit, Command, Stdio},
    sync::LazyLock,
};
use toml_edit::{value as toml_value, Array, DocumentMut as Document};

pub use super::common::*;

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__DEV__", &*BASE_DIR));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<C, P, U>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
            Op::Create(opts) => Env::<C, P, S>::create(self, opts, s).c(d!()),
            Op::Destroy(force) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.destroy(*force).c(d!())),
            Op::DestroyAll(force) => Env::<C, P, S>::destroy_all(*force).c(d!()),
            Op::PushNode(is_archive) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    env.push_node(alt!(
                        *is_archive,
                        NodeKind::ArchiveNode,
                        NodeKind::FullNode
                    ))
                    .c(d!())
                }),
            Op::KickNode(node_id) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node(*node_id).c(d!())),
            Op::Protect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start(node_id) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.launch(*node_id).c(d!())),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop((node_id, force)) => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.stop(*node_id, *force).c(d!())),
            Op::StopAll(force) => Env::<C, P, S>::stop_all(*force).c(d!()),
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
    #[serde(rename = "env_home_dir")]
    pub home: String,

    pub host_ip: String,

    /// Seconds between two blocks
    #[serde(rename = "block_interval_in_seconds")]
    pub block_itv_secs: BlockItv,

    #[serde(rename = "bootstrap_nodes")]
    pub bootstraps: BTreeMap<NodeID, N>,

    pub nodes: BTreeMap<NodeID, N>,

    /// The genesis tar package, gzip compressed
    #[serde(rename = "genesis_collections")]
    pub genesis: Option<GenesisTgz>,

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
        let node = self.bootstraps.values().chain(self.nodes.values()).next();
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
    pub node_cmd_generator: S,
}

impl<C, P, S> Env<C, P, S>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
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
                block_itv_secs: opts.block_itv_secs,
                nodes: Default::default(),
                bootstraps: Default::default(),
                genesis: None,
                custom_data: opts.custom_data.clone(),
                next_node_id: Default::default(),
            },
            is_protected: true,
            node_cmd_generator: s,
        };

        fs::create_dir_all(&env.meta.home).c(d!())?;

        macro_rules! add_initial_nodes {
            ($kind: expr) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, $kind).c(d!())?;
            }};
        }

        add_initial_nodes!(NodeKind::Bootstrap);
        for _ in 0..opts.initial_node_num {
            add_initial_nodes!(alt!(
                opts.initial_nodes_archive,
                NodeKind::ArchiveNode,
                NodeKind::FullNode
            ));
        }

        env.gen_genesis(&opts.egg_path)
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start().c(d!()))
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

        // DO NOT USE `node.destroy(...)` here,
        // we should NOT wait 100ms for every node,
        // once is enough!
        info_omit!(self.stop(None, true));

        // Wait all nodes to be actually stopped
        sleep_ms!(100);

        for n in self
            .meta
            .bootstraps
            .values()
            .chain(self.meta.nodes.values())
        {
            n.clean_up().c(d!())?;
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

    // bootstrap nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(&mut self, kind: NodeKind) -> Result<()> {
        let id = self.next_node_id();
        self.alloc_resources(id, kind)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start_node(id).c(d!()))
    }

    // The bootstrap node should not be removed
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
            .and_then(|n| n.destroy(self).c(d!()))
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

    #[inline(always)]
    fn start(&mut self) -> Result<()> {
        self.launch(None).c(d!())
    }

    #[inline(always)]
    fn start_node(&mut self, n: NodeID) -> Result<()> {
        self.launch(Some(n)).c(d!())
    }

    // Start one or all nodes
    fn launch(&mut self, n: Option<NodeID>) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_peer_cfg()
            .c(d!())
            .and_then(|_| self.write_cfg().c(d!()))?;

        for i in ids.iter() {
            if let Some(n) = self
                .meta
                .bootstraps
                .get(i)
                .or_else(|| self.meta.nodes.get(i))
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
                .start()
                .c(d!())?;
        }
        Ok(())
    }

    // - Stop all processes
    // - Release all occupied ports
    #[inline(always)]
    fn stop(&self, n: Option<NodeID>, force: bool) -> Result<()> {
        self.kill(n, force, false).c(d!())
    }

    fn kill(&self, n: Option<NodeID>, force: bool, destroy: bool) -> Result<()> {
        let mut nodes = self
            .meta
            .bootstraps
            .values()
            .chain(self.meta.nodes.values());

        let nodes = if let Some(id) = n {
            vec![nodes.find(|n| n.id == id).c(d!())?]
        } else {
            nodes.collect::<Vec<_>>()
        };

        nodes
            .into_iter()
            .map(|n| alt!(destroy, n.destroy(self), n.stop(self, force)).c(d!()))
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

    // TODO
    // 1. Allocate ports
    // 2. Change configs: ports, bootstrap address, etc
    // 3. Insert new node to the meta of env
    // 4. Write new configs of beacon to disk
    fn alloc_resources(&mut self, id: NodeID, kind: NodeKind) -> Result<()> {
        todo!()
    }

    // Global alloctor for ports
    fn alloc_ports(&self, node_kind: &NodeKind) -> Result<P> {
        let reserved_ports = P::reserved();

        let mut res = vec![];

        if matches!(node_kind, NodeKind::Bootstrap)
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

    // TODO
    // randomly select some nodes:
    //   - update bootnodes for all clients
    //   - update trusted peers for lighthouse and reth
    fn update_peer_cfg(&self) -> Result<()> {
        for n in self
            .meta
            .nodes
            .values()
            .chain(self.meta.bootstraps.values())
        {
            todo!()
        }

        Ok(())
    }

    // Allocate unique IDs for nodes within the scope of an env
    fn next_node_id(&mut self) -> NodeID {
        let ret = self.meta.next_node_id;
        self.meta.next_node_id += 1;
        ret
    }

    // TODO
    // call `egg` to generate the genesis data
    fn gen_genesis(&mut self, egg_path: &str) -> Result<()> {
        todo!()
    }

    // TODO
    // Apply genesis to one/all nodes in the same env
    fn apply_genesis(&mut self, n: Option<NodeID>) -> Result<()> {
        let nodes = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        for n in nodes.iter() {
            self.meta
                .nodes
                .get(n)
                .or_else(|| self.meta.bootstraps.get(n))
                .c(d!())
                .and_then(|n| todo!())?;
        }

        Ok(())
    }

    #[inline(always)]
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        EnvMeta::<C, Node<P>>::get_env_list().c(d!())
    }

    fn load_env_by_cfg<U>(cfg: &EnvCfg<C, P, U>) -> Result<Env<C, P, S>>
    where
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
        serde_json::to_vec_pretty(self)
            .c(d!())
            .and_then(|d| fs::write(format!("{}/CONFIG", &self.meta.home), d).c(d!()))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    pub id: NodeID,
    #[serde(rename = "node_home_dir")]
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
        if env.node_cmd_generator.is_running(self, &env.meta).c(d!())? {
            return Err(eg!("This node({}, {}) is running ...", self.id, self.home));
        }

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Child) => {
                let cmd = env.node_cmd_generator.cmd_for_start(self, &env.meta);
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
        let cmd = env.node_cmd_generator.cmd_for_stop(self, &env.meta, force);
        let outputs = cmd::exec_output(&cmd).c(d!())?;
        let contents = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&contents).c(d!())
    }

    // - Stop the node
    // - Release all occupied ports
    // - Remove all files related to this node
    fn destroy<C, S>(&self, env: &Env<C, P, S>) -> Result<()>
    where
        C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        self.stop(env, true).c(d!())?;

        // Wait the node to be actually stopped
        sleep_ms!(100);

        self.clean_up().c(d!())
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
    fn clean_up(&self) -> Result<()> {
        for port in self.ports.get_port_list().into_iter() {
            PortsCache::remove(port).c(d!())?;
        }
        fs::remove_dir_all(&self.home).c(d!())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum NodeKind {
    Bootstrap = 0,
    ArchiveNode = 1,
    FullNode = 2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<C, P, U>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create(EnvOpts<C>),
    Destroy(bool),    // force or not
    DestroyAll(bool), // force or not
    PushNode(bool),   // require an archive node or not
    KickNode(Option<NodeID>),
    Protect,
    Unprotect,
    Start(Option<NodeID>),
    StartAll,
    Stop((Option<NodeID>, bool)), // force or not
    StopAll(bool),                // force or not
    Show,
    ShowAll,
    List,
    Custom(U),
    Nil(P),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<C>
where
    C: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Default to '127.0.0.1'
    pub host_ip: String,

    /// Seconds between two blocks
    pub block_itv_secs: BlockItv,

    /// How many initial nodes should be created,
    /// default to 4(include the bootstrap node)
    pub initial_node_num: u8,

    #[serde(default = "initial_nodes_archive_default")]
    pub initial_nodes_archive: bool,

    // Ethereum Genesis Generator
    pub egg_path: String,

    pub custom_data: C,

    pub force_create: bool,
}

#[inline(always)]
fn initial_nodes_archive_default() -> bool {
    true
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
    let cmd = format!("ulimit -n 100000; {}", cmd);
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
        .map(|exit_status| println!("{}", exit_status))
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
