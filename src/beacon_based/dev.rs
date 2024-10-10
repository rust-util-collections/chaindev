//!
//! Localhost version
//!

use nix::{
    sys::socket::{
        self, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType,
        SockaddrIn,
    },
    unistd::{self, ForkResult},
};
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::io::AsRawFd,
    process::{exit, Command, Stdio},
    sync::LazyLock,
};
use vsdb::MapxOrd;

pub use super::common::*;

static GLOBAL_BASE_DIR: LazyLock<String> =
    LazyLock::new(|| format!("{}/__DEV__", &*BASE_DIR));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<Data, Ports, Ops>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
    Ops: CustomOps,
{
    /// The name of this env
    pub name: EnvName,

    /// Which operation to trigger/call
    pub op: Op<Data, Ports, Ops>,
}

impl<Data, Ports, Ops> EnvCfg<Data, Ports, Ops>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
    Ops: CustomOps,
{
    pub fn exec<Cmds>(&self, s: Cmds) -> Result<()>
    where
        Ports: NodePorts,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
    {
        match &self.op {
            Op::Create(opts) => Env::<Data, Ports, Cmds>::create(self, opts, s).c(d!()),
            Op::Destroy(force) => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.destroy(*force).c(d!())),
            Op::DestroyAll(force) => {
                Env::<Data, Ports, Cmds>::destroy_all(*force).c(d!())
            }
            Op::PushNode((node_mark, is_archive)) => {
                Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        env.push_node(
                            alt!(
                                *is_archive,
                                NodeKind::ArchiveNode,
                                NodeKind::FullNode
                            ),
                            Some(*node_mark),
                        )
                        .c(d!())
                    })
            }
            Op::KickNode(node_id) => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node(*node_id).c(d!())),
            Op::Protect => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start(node_id) => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.launch(*node_id).c(d!())),
            Op::StartAll => Env::<Data, Ports, Cmds>::start_all().c(d!()),
            Op::Stop((node_id, force)) => {
                Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| env.stop(*node_id, *force).c(d!()))
            }
            Op::StopAll(force) => Env::<Data, Ports, Cmds>::stop_all(*force).c(d!()),
            Op::Show => {
                Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                    .c(d!())
                    .map(|env| {
                        env.show();
                    })
            }
            Op::ShowAll => Env::<Data, Ports, Cmds>::show_all().c(d!()),
            Op::List => Env::<Data, Ports, Cmds>::list_all().c(d!()),
            Op::Custom(custom_op) => custom_op.exec(&self.name).c(d!()),
            Op::Nil(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct EnvMeta<Data, N>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    N: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// The name of this env
    #[serde(flatten)]
    pub name: EnvName,

    /// The data path of this env
    #[serde(rename = "env_home")]
    pub home: String,

    /// Eg.
    /// - "127.0.0.1"
    /// - "localhost"
    pub host_ip: String,

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

    /// The first Fuck node
    /// will be treated as the genesis node
    #[serde(rename = "fuck_nodes")]
    pub fucks: BTreeMap<NodeID, N>,

    /// Non-fuck node collection
    pub nodes: BTreeMap<NodeID, N>,

    /// An in-memory cache for recording node status
    pub nodes_should_be_online: MapxOrd<NodeID, ()>,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: Data,

    /// Node ID allocator
    pub(crate) next_node_id: NodeID,
}

impl<Data, Ports> EnvMeta<Data, Node<Ports>>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
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

    pub fn load_env_by_name<Cmds>(
        cfg_name: &EnvName,
    ) -> Result<Option<Env<Data, Ports, Cmds>>>
    where
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
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
        let node = self.fucks.values().chain(self.nodes.values()).next();
        let ports = pnk!(node).ports.get_port_list();
        (addr, ports)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<Data, Ports, Cmds>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
    Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
{
    pub meta: EnvMeta<Data, Node<Ports>>,
    pub is_protected: bool,
    pub node_cmdline_generator: Cmds,
}

impl<Data, Ports, Cmds> Env<Data, Ports, Cmds>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
    Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
{
    // - Initilize a new env
    // - Create `genesis.json`
    fn create<Ops>(
        cfg: &EnvCfg<Data, Ports, Ops>,
        opts: &EnvOpts<Data>,
        s: Cmds,
    ) -> Result<()>
    where
        Ops: CustomOps,
    {
        let home = format!("{}/envs/{}", &*GLOBAL_BASE_DIR, &cfg.name);

        if opts.force_create {
            if let Ok(mut env) = Env::<Data, Ports, Cmds>::load_env_by_cfg(cfg) {
                env.destroy(true).c(d!())?;
            }
            omit!(fs::remove_dir_all(&home));
        }

        if fs::metadata(&home).is_ok() {
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
                host_ip: opts.host_ip.clone(),
                block_itv: opts.block_itv,
                genesis_pre_settings: opts.genesis_pre_settings.clone(),
                genesis,
                genesis_vkeys,
                fucks: Default::default(),
                nodes: Default::default(),
                nodes_should_be_online: MapxOrd::new(),
                custom_data: opts.custom_data.clone(),
                next_node_id: Default::default(),
            },
            is_protected: true,
            node_cmdline_generator: s,
        };

        fs::create_dir_all(&env.meta.home).c(d!())?;

        macro_rules! add_initial_nodes {
            ($kind: expr) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, $kind, None).c(d!())?;
            }};
        }

        add_initial_nodes!(NodeKind::Fuck);
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
            .and_then(|_| env.start().c(d!()))
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

        // DO NOT USE `node.destroy(...)` here,
        // we should NOT waste(dup) time for each node
        info_omit!(self.stop(None, true));

        // Wait all nodes to be actually stopped
        sleep_ms!(200);

        for n in self.meta.fucks.values().chain(self.meta.nodes.values()) {
            n.clean_up().c(d!())?;
        }

        fs::remove_dir_all(&self.meta.home).c(d!())
    }

    // destroy all existing ENVs
    fn destroy_all(force: bool) -> Result<()> {
        for name in Self::get_env_list().c(d!())?.iter() {
            let mut env = Self::load_env_by_name(name)
                .c(d!())?
                .c(d!("BUG: the ENV recorded, but not found"))?;
            env.destroy(force).c(d!())?;
        }

        Ok(())
    }

    // Fuck nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(&mut self, kind: NodeKind, mark: Option<NodeMark>) -> Result<()> {
        let id = self.next_node_id();
        self.alloc_resources(id, kind, mark)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start_node(id).c(d!()))
    }

    // Kick out a target node, or a randomly selected one,
    // NOTE: the fuck node will never be kicked
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
                .c(d!("No kickable nodes found"))?
        };

        self.update_online_status(&[], &[id]);

        self.meta
            .nodes
            .remove(&id)
            .c(d!("Node id does not exist?"))
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

    // Start one or all nodes of the ENV
    fn launch(&mut self, n: Option<NodeID>) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .fucks
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_online_status(&ids, &[]);

        for i in ids.iter() {
            if let Some(n) = self.meta.fucks.get(i).or_else(|| self.meta.nodes.get(i)) {
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
    fn stop(&mut self, n: Option<NodeID>, force: bool) -> Result<()> {
        if let Some(id) = n {
            if let Some(n) = self
                .meta
                .nodes
                .get(&id)
                .or_else(|| self.meta.fucks.get(&id))
            {
                n.stop(self, force)
                    .c(d!())
                    .map(|_| self.update_online_status(&[], &[id]))
            } else {
                Err(eg!("The target node not found"))
            }
        } else {
            // Need NOT to call the `update_online_status`
            // for an entire stopped ENV, meaningless
            self.meta
                .fucks
                .values()
                .chain(self.meta.nodes.values())
                .map(|n| n.stop(self, force).c(d!()))
                .collect::<Result<Vec<_>>>()
                .map(|_| ())
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

        for i in ["nodes", "fuck_nodes"] {
            for n in meta[i].as_object_mut().unwrap().values_mut() {
                let n = n.as_object_mut().unwrap();
                let mark = n.remove("mark").unwrap();
                let mark = alt!(mark.as_null().is_some(), 0, mark.as_u64().unwrap());
                n.insert("el_type".to_owned(), alt!(0 == mark, "geth", "reth").into());
                n.insert("cl_type".to_owned(), "lighthouse".into());
            }
        }

        meta.remove("nodes_should_be_online");

        if !meta["genesis"].take().as_array().unwrap().is_empty() {
            meta["genesis"] = Value::String("SET".to_owned());
        }

        if !meta["genesis_vkeys"].take().as_array().unwrap().is_empty() {
            meta["genesis_vkeys"] = Value::String("SET".to_owned());
        }

        if !meta["genesis_pre_settings"]
            .take()
            .as_str()
            .unwrap()
            .is_empty()
        {
            meta["genesis_pre_settings"] = Value::String("SET".to_owned());
        }

        println!("{}", pnk!(serde_json::to_string_pretty(&ret)));
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

    // 1. Allocate home dir, ports ..
    // 2. Record the node in its ENV meta
    fn alloc_resources(
        &mut self,
        id: NodeID,
        kind: NodeKind,
        mark: Option<NodeMark>,
    ) -> Result<()> {
        // 1.
        let home = format!("{}/{}", &self.meta.home, id);
        fs::create_dir_all(&home).c(d!())?;

        let ports = self.alloc_ports(&kind).c(d!())?;

        // 2.
        let node = Node {
            id,
            home,
            kind,
            ports,
            mark,
        };

        match kind {
            NodeKind::FullNode | NodeKind::ArchiveNode => {
                self.meta.nodes.insert(id, node)
            }
            NodeKind::Fuck => self.meta.fucks.insert(id, node),
        };

        self.write_cfg().c(d!())
    }

    // Global alloctor for ports
    fn alloc_ports(&self, node_kind: &NodeKind) -> Result<Ports> {
        let reserved_ports = Ports::reserved();

        let mut res = vec![];

        if matches!(node_kind, NodeKind::Fuck)
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

        Ports::try_create(&res).c(d!())
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
                    cp {cfg}.minimal.example {cfg} || exit 1
                fi
                if [ 0 -lt {0} ]; then
                    sed -i '/SLOT_DURATION_IN_SECONDS/d' {cfg} || exit 1
                    echo 'export SLOT_DURATION_IN_SECONDS="{0}"' >>{cfg} || exit 1
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
            let cmd = format!("tar -xpf {genesis} && cp {tmpdir}/*/config.yaml {yml}");
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

    // Apply genesis to node[s]:
    // - copy the xx.tar.gz to the destinaton
    // - extract it
    fn apply_genesis(&mut self, id: Option<NodeID>) -> Result<()> {
        if self.meta.genesis.is_empty() || self.meta.genesis_vkeys.is_empty() {
            return Err(eg!("BUG: no genesis data"));
        }

        let nodes = if let Some(id) = id {
            self.meta
                .nodes
                .get(&id)
                .or_else(|| self.meta.fucks.get(&id))
                .c(d!())
                .map(|n| vec![n])?
        } else {
            self.meta
                .fucks
                .values()
                .chain(self.meta.nodes.values())
                .collect()
        };

        let genesis_node_id = *self.meta.fucks.keys().next().c(d!())?;

        let mut p;
        for n in nodes.iter() {
            p = format!("{}/{NODE_HOME_GENESIS_DST}", n.home.as_str());
            fs::write(&p, &self.meta.genesis).c(d!())?;

            if n.id == genesis_node_id {
                p = format!("{}/{NODE_HOME_VCDATA_DST}", n.home.as_str());
                fs::write(&p, &self.meta.genesis_vkeys).c(d!())?;
            }
        }

        Ok(())
    }

    #[inline(always)]
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        EnvMeta::<Data, Node<Ports>>::get_env_list().c(d!())
    }

    fn load_env_by_cfg<Ops>(
        cfg: &EnvCfg<Data, Ports, Ops>,
    ) -> Result<Env<Data, Ports, Cmds>>
    where
        Ops: CustomOps,
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
    pub fn load_env_by_name(
        cfg_name: &EnvName,
    ) -> Result<Option<Env<Data, Ports, Cmds>>> {
        EnvMeta::<Data, Node<Ports>>::load_env_by_name(cfg_name).c(d!())
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
pub struct Node<Ports: NodePorts> {
    pub id: NodeID,
    #[serde(rename = "node_home")]
    pub home: String,
    pub ports: Ports,
    pub kind: NodeKind,
    pub mark: Option<NodeMark>, // custom mark set by USER
}

impl<Ports: NodePorts> Node<Ports> {
    fn start<Data, Cmds>(&self, env: &Env<Data, Ports, Cmds>) -> Result<()>
    where
        Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
    {
        let cmd = env.node_cmdline_generator.cmd_cnt_running(self, &env.meta);
        let process_cnt = cmd::exec_output(&cmd)
            .c(d!(&cmd))?
            .trim()
            .parse::<u64>()
            .c(d!())?;
        if 0 < process_cnt {
            return Err(eg!("This node({}, {}) is running ...", self.id, self.home));
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

    fn stop<Data, Cmds>(&self, env: &Env<Data, Ports, Cmds>, force: bool) -> Result<()>
    where
        Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
    {
        let cmd = env
            .node_cmdline_generator
            .cmd_for_stop(self, &env.meta, force);
        let outputs = cmd::exec_output(&cmd).c(d!(&cmd))?;
        let contents = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&contents).c(d!())
    }

    // - Stop the node
    // - Release all occupied ports
    // - Remove all files related to this node
    fn destroy<Data, Cmds>(&self, env: &Env<Data, Ports, Cmds>) -> Result<()>
    where
        Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<Data, Ports, Ops>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    Ports: NodePorts,
    Ops: CustomOps,
{
    Create(EnvOpts<Data>),
    Destroy(bool),              // force or not
    DestroyAll(bool),           // force or not
    PushNode((NodeMark, bool)), // for archive node, set `true`; full node set `false`
    KickNode(Option<NodeID>),
    Protect,
    Unprotect,
    Start(Option<NodeID>),
    StartAll,
    Stop((Option<NodeID>, bool)), // force(kill -9) or not
    StopAll(bool),                // force(kill -9) or not
    Show,
    ShowAll,
    List,
    Custom(Ops),
    Nil(Ports),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<Data>
where
    Data: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Eg.
    /// - '127.0.0.1'
    pub host_ip: String,

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
    /// including the fuck node
    pub initial_node_num: u8,

    /// Set nodes as ArchiveNode by default
    pub initial_nodes_fullnode: bool,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: Data,

    /// Try to destroy env with the same name,
    /// and create a new one
    pub force_create: bool,
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
    let cmd = format!("ulimit -n 102400; {}", cmd);
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
