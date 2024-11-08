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
use serde_json::Value as JsonValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
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
    Data: CustomData,
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
    Data: CustomData,
    Ports: NodePorts,
    Ops: CustomOps,
{
    pub fn exec<Cmds>(&self, s: Cmds) -> Result<()>
    where
        Ports: NodePorts,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
    {
        match &self.op {
            Op::Create { opts } => {
                Env::<Data, Ports, Cmds>::create(self, opts, s).c(d!())
            }
            Op::Destroy { force } => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.destroy(*force).c(d!())),
            Op::PushNodes {
                custom_data,
                fullnode,
                num,
            } => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    for i in 1..=*num {
                        let id = env
                            .push_node(
                                alt!(
                                    *fullnode,
                                    NodeKind::FullNode,
                                    NodeKind::ArchiveNode,
                                ),
                                Some(custom_data.clone()),
                            )
                            .c(d!())?;
                        println!("The {i}th new node has been created, NodeID: {id}");
                    }
                    Ok(())
                }),
            Op::KickNodes { nodes, num, force } => {
                Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        if let Some(ids) = nodes {
                            for (i, id) in ids.iter().copied().enumerate() {
                                let id_returned =
                                    env.kick_node(Some(id), *force).c(d!())?;
                                assert_eq!(id, id_returned);
                                println!(
                                    "The {}th node has been kicked, NodeID: {id}",
                                    1 + i
                                );
                            }
                        } else {
                            for i in 1..=*num {
                                let id = env.kick_node(None, *force).c(d!())?;
                                println!(
                                    "The {i}th node has been kicked, NodeID: {id}",
                                );
                            }
                        }
                        Ok(())
                    })
            }
            Op::Protect => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.protect().c(d!())),
            Op::Unprotect => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.unprotect().c(d!())),
            Op::Start {
                nodes,
                ignore_failed,
            } => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = nodes {
                        for (i, id) in ids.iter().copied().enumerate() {
                            env.start(Some(id), *ignore_failed).c(d!())?;
                            println!(
                                "The {}th node has been started, NodeID: {id}",
                                1 + i
                            );
                        }
                        Ok(())
                    } else {
                        env.start(None, *ignore_failed).c(d!())
                    }
                }),
            Op::Stop { nodes, force } => {
                Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|mut env| {
                        if let Some(ids) = nodes {
                            for (i, id) in ids.iter().copied().enumerate() {
                                env.stop(Some(id), *force).c(d!())?;
                                println!(
                                    "The {}th node has been stopped, NodeID: {id}",
                                    1 + i
                                );
                            }
                            Ok(())
                        } else {
                            env.stop(None, *force).c(d!())
                        }
                    })
            }
            Op::Restart {
                nodes,
                ignore_failed,
                wait_itv_secs,
            } => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| {
                    if let Some(ids) = nodes {
                        for (i, id) in ids.iter().copied().enumerate() {
                            env.restart(Some(id), *ignore_failed, *wait_itv_secs)
                                .c(d!())?;
                            println!(
                                "The {}th node has been restarted, NodeID: {id}",
                                1 + i
                            );
                        }
                        Ok(())
                    } else {
                        env.restart(None, *ignore_failed, *wait_itv_secs).c(d!())
                    }
                }),
            Op::DebugFailedNodes => Env::<Data, Ports, Cmds>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.debug_failed_nodes().c(d!())),
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
    Data: CustomData,
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

    /// An in-memory cache for recording node status
    pub nodes_should_be_online: MapxOrd<NodeID, ()>,

    /// Data data may be useful when cfg/running nodes,
    /// such as the info about execution client(reth or geth)
    pub custom_data: Data,

    // Node ID allocator
    next_node_id: NodeID,
}

impl<Data, Ports> EnvMeta<Data, Node<Ports>>
where
    Data: CustomData,
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
        let node = self.fuhrers.values().chain(self.nodes.values()).next();
        let ports = pnk!(node).ports.get_port_list();
        (addr, ports)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<Data, Ports, Cmds>
where
    Data: CustomData,
    Ports: NodePorts,
    Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
{
    pub meta: EnvMeta<Data, Node<Ports>>,
    pub is_protected: bool,
    pub node_cmdline_generator: Cmds,
}

impl<Data, Ports, Cmds> Env<Data, Ports, Cmds>
where
    Data: CustomData,
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
                git config user.name x && \
                echo '# ENV: {}' > README.md && \
                git add README.md && \
                git commit -m 'Initial commit'
                "#,
                env.meta.home,
                env.meta.name
            );
            cmd::exec_output(&cmd).c(d!())
        })?;

        let id = env.next_node_id();
        env.alloc_resources(id, NodeKind::Fuhrer, None).c(d!())?;

        env.gen_genesis()
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None, false).c(d!()))
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

        for n in self.meta.fuhrers.values().chain(self.meta.nodes.values()) {
            n.clean_up().c(d!())?;
        }

        fs::remove_dir_all(&self.meta.home).c(d!())
    }

    // // destroy all existing ENVs
    // fn destroy_all(force: bool) -> Result<()> {
    //     for name in Self::get_env_list().c(d!())?.iter() {
    //         let mut env = Self::load_env_by_name(name)
    //             .c(d!())?
    //             .c(d!("BUG: the ENV recorded, but not found"))?;
    //         env.destroy(force).c(d!())?;
    //     }

    //     Ok(())
    // }

    // Fuhrer nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(
        &mut self,
        kind: NodeKind,
        custom_data: Option<NodeCustomData>,
    ) -> Result<NodeID> {
        let id = self.next_node_id();
        self.alloc_resources(id, kind, custom_data)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start(Some(id), false).c(d!()))
            .map(|_| id)
    }

    // Kick out a target node, or a randomly selected one,
    // NOTE: the fuhrer node will never be kicked
    fn kick_node(&mut self, node_id: Option<NodeID>, force: bool) -> Result<NodeID> {
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
                .c(d!("No kickable nodes found"))?
        };

        if self.meta.fuhrers.contains_key(&id) {
            return Err(eg!("Node-[{}] is a fuhrer node, deny to kick", id));
        }

        self.meta
            .nodes
            .remove(&id)
            .c(d!("Node id does not exist?"))
            .and_then(|n| {
                self.update_online_status(&[], &[id]);
                n.destroy(self).c(d!())
            })
            .and_then(|_| self.write_cfg().c(d!()))
            .map(|_| id)
    }

    fn protect(&mut self) -> Result<()> {
        self.is_protected = true;
        self.write_cfg().c(d!())
    }

    fn unprotect(&mut self) -> Result<()> {
        self.is_protected = false;
        self.write_cfg().c(d!())
    }

    // Start one or all nodes of the ENV
    fn start(&mut self, n: Option<NodeID>, ignore_failed: bool) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .fuhrers
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_online_status(&ids, &[]);

        for i in ids.iter() {
            if let Some(n) = self.meta.fuhrers.get(i).or_else(|| self.meta.nodes.get(i))
            {
                let r = n.start(self).c(d!());
                if !ignore_failed {
                    r?;
                }
            } else {
                return Err(eg!("not exist"));
            }
        }

        Ok(())
    }

    // // Start all existing ENVs
    // fn start_all() -> Result<()> {
    //     for env in Self::get_env_list().c(d!())?.iter() {
    //         Self::load_env_by_name(env)
    //             .c(d!())?
    //             .c(d!("BUG: env not found!"))?
    //             .start(None, false)
    //             .c(d!())?;
    //     }
    //     Ok(())
    // }

    // - Stop all processes
    // - Release all occupied ports
    #[inline(always)]
    fn stop(&mut self, n: Option<NodeID>, force: bool) -> Result<()> {
        if let Some(id) = n {
            if let Some(n) = self
                .meta
                .nodes
                .get(&id)
                .or_else(|| self.meta.fuhrers.get(&id))
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
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .map(|n| n.stop(self, force).c(d!()))
                .collect::<Result<Vec<_>>>()
                .map(|_| ())
        }
    }

    // // Stop all existing ENVs
    // fn stop_all(force: bool) -> Result<()> {
    //     for env in Self::get_env_list().c(d!())?.iter() {
    //         Self::load_env_by_name(env)
    //             .c(d!())?
    //             .c(d!("BUG: env not found!"))?
    //             .stop(None, force)
    //             .c(d!())?;
    //     }
    //     Ok(())
    // }

    // Restart one or all nodes
    fn restart(
        &mut self,
        id: Option<NodeID>,
        ignore_failed: bool,
        wait_itv_secs: u8,
    ) -> Result<()> {
        let mut nodes = vec![];

        if let Some(id) = id {
            if self.meta.nodes.contains_key(&id) || self.meta.fuhrers.contains_key(&id)
            {
                nodes.push(id);
            } else {
                return Err(eg!("The node(id: {}) does not exist", id));
            }
        } else {
            for id in self.meta.fuhrers.keys().chain(self.meta.nodes.keys()) {
                nodes.push(*id);
            }
        };

        for n in nodes.iter().copied() {
            self.stop(Some(n), false).c(d!())?;
            sleep_ms!(1000 * wait_itv_secs as u64);
            self.start(Some(n), ignore_failed).c(d!())?;
        }

        Ok(())
    }

    fn debug_failed_nodes(&self) -> Result<()> {
        let mut failed_cases = vec![];

        for n in self.meta.nodes.values().chain(self.meta.fuhrers.values()) {
            let cmd = self.node_cmdline_generator.cmd_cnt_running(n, &self.meta);
            let process_cnt = cmd::exec_output(&cmd)
                .c(d!(&cmd))?
                .trim()
                .parse::<u64>()
                .c(d!())?;
            if 3 > process_cnt {
                failed_cases.push(n.id);
            }
        }

        serde_json::to_string_pretty(&failed_cases)
            .c(d!())
            .map(|s| println!("{s}"))
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
        custom_data: Option<NodeCustomData>,
    ) -> Result<()> {
        // 1.
        let home = format!("{}/{}", &self.meta.home, id);
        fs::create_dir_all(&home).c(d!())?;

        let ports = Self::alloc_ports(&kind).c(d!())?;

        // 2.
        let node = Node {
            id,
            home,
            kind,
            ports,
            custom_data,
        };

        match kind {
            NodeKind::FullNode | NodeKind::ArchiveNode => {
                self.meta.nodes.insert(id, node)
            }
            NodeKind::Fuhrer => self.meta.fuhrers.insert(id, node),
        };

        self.write_cfg().c(d!())
    }

    // Global alloctor for ports
    fn alloc_ports(node_kind: &NodeKind) -> Result<Ports> {
        let reserved_ports = Ports::reserved();

        let mut res = vec![];

        if matches!(node_kind, NodeKind::Fuhrer)
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
                    cp {cfg}.minimal.example {cfg} || exit 1
                fi
                if [ 0 -lt {0} ]; then
                    sed -i '/SLOT_DURATION_IN_SECONDS/d' {cfg} || exit 1
                    echo 'export SLOT_DURATION_IN_SECONDS="{0}"' >>{cfg} || exit 1
                fi
                grep -Po '(?<= SLOT_DURATION_IN_SECONDS=")\d+' {cfg} >{block_itv_cache} || exit 1
                make minimal_prepare || exit 1
                make build || exit 1
                cp -r {repo}/data/{NODE_HOME_GENESIS_DIR_DST} {1}/ || exit 1
                cp -r {1}/{NODE_HOME_GENESIS_DIR_DST} {1}/{NODE_HOME_GENESIS_DIR_DST_PUBLIC} || exit 1
                cd {1}/{NODE_HOME_GENESIS_DIR_DST_PUBLIC} || exit 1
                rm -rf tranches mnemonics.yaml || exit 1
                sed -ri 's/("secretKey":)\s".*"/\1 ""/' genesis.json || exit 1
                sed -ri 's/("secretKey":)\s".*"/\1 ""/' chainspec.json || exit 1
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
                tar -xf {genesis} || exit 1
                cp -r {NODE_HOME_GENESIS_DIR_DST} {0}/ || exit 1
                cp -r {0}/{NODE_HOME_GENESIS_DIR_DST} {0}/{NODE_HOME_GENESIS_DIR_DST_PUBLIC} || exit 1
                cd {0}/{NODE_HOME_GENESIS_DIR_DST_PUBLIC} || exit 1
                rm -rf tranches mnemonics.yaml || exit 1
                sed -ri 's/("secretKey":)\s".*"/\1 ""/' genesis.json || exit 1
                sed -ri 's/("secretKey":)\s".*"/\1 ""/' chainspec.json || exit 1
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

        self.write_cfg().c(d!())?;

        let cmd = format!(
            "cd {} && git add {NODE_HOME_GENESIS_DIR_DST_PUBLIC}",
            self.meta.home
        );
        cmd::exec_output(&cmd).c(d!()).map(|_| ())
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
                .or_else(|| self.meta.fuhrers.get(&id))
                .c(d!())
                .map(|n| vec![n])?
        } else {
            self.meta
                .fuhrers
                .values()
                .chain(self.meta.nodes.values())
                .collect()
        };

        let genesis_node_id = *self.meta.fuhrers.first_key_value().c(d!())?.0;

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
pub struct Node<Ports: NodePorts> {
    pub id: NodeID,
    #[serde(rename = "node_home")]
    pub home: String,
    pub ports: Ports,
    pub kind: NodeKind,

    // custom data set by USER
    pub custom_data: Option<NodeCustomData>,
}

impl<Ports: NodePorts> Node<Ports> {
    fn start<Data, Cmds>(&self, env: &Env<Data, Ports, Cmds>) -> Result<()>
    where
        Data: CustomData,
        Cmds: NodeCmdGenerator<Node<Ports>, EnvMeta<Data, Node<Ports>>>,
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
                    self.id,
                    process_cnt
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

    fn stop<Data, Cmds>(&self, env: &Env<Data, Ports, Cmds>, force: bool) -> Result<()>
    where
        Data: CustomData,
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
        Data: CustomData,
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
            .open(format!("{}/{MGMT_OPS_LOG}", &self.home))
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
    Data: CustomData,
    Ports: NodePorts,
    Ops: CustomOps,
{
    Create {
        opts: EnvOpts<Data>,
    },
    Destroy {
        force: bool,
    },
    PushNodes {
        custom_data: NodeCustomData,
        fullnode: bool, /*for archive node set `false`*/
        num: u8,        /*how many new nodes to add*/
    },
    KickNodes {
        nodes: Option<BTreeSet<NodeID>>,
        num: u8, /*how many nodes to kick if no specific ids are specified*/
        force: bool,
    },
    Protect,
    Unprotect,
    Start {
        nodes: Option<BTreeSet<NodeID>>,
        ignore_failed: bool, /*ignore failed cases or not*/
    },
    Stop {
        nodes: Option<BTreeSet<NodeID>>,
        force: bool, /*force(kill -9) or not*/
    },
    Restart {
        nodes: Option<BTreeSet<NodeID>>,
        ignore_failed: bool, /*ignore failed cases or not*/
        wait_itv_secs: u8,   /*Seconds to wait between the `stop` and `start` ops*/
    },
    DebugFailedNodes,
    List,
    Custom(Ops),
    Nil(Ports),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<Data: CustomData> {
    /// Eg.
    /// - '127.0.0.1'
    pub host_ip: String,

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
