//!
//! Localhost version.
//!

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
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::PathBuf,
    process::{exit, Command, Stdio},
    str::FromStr,
};
use tendermint::{validator::Info as TmValidator, vote::Power as TmPower};
use tendermint_config::{
    PrivValidatorKey as TmValidatorKey, TendermintConfig as TmConfig,
};
use toml_edit::{value as toml_value, Array, Document};

pub use super::common::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvCfg {
    // the name of this env
    pub name: EnvName,

    /// which operation to trigger
    pub op: Op,
}

impl EnvCfg {
    pub fn exec<P: NodePorts, S: NodeOptsGenerator<Node<P>>>(
        &self,
        s: S,
    ) -> Result<Option<Env<P, S>>> {
        match &self.op {
            Op::Create(opts) => Env::<P, S>::create(self, opts, s).c(d!()).map(Some),
            Op::Destroy => Env::<P, S>::load_cfg(self)
                .c(d!())
                .and_then(|env| env.destroy().c(d!()))
                .map(|_| None),
            Op::DestroyAll => Env::<P, S>::destroy_all().c(d!()).map(|_| None),
            Op::Start => Env::<P, S>::load_cfg(self)
                .c(d!())
                .and_then(|mut env| env.start(None).c(d!()))
                .map(|_| None),
            Op::StartAll => Env::<P, S>::start_all().c(d!()).map(|_| None),
            Op::Stop => Env::<P, S>::load_cfg(self)
                .c(d!())
                .and_then(|env| env.stop().c(d!()))
                .map(|_| None),
            Op::StopAll => Env::<P, S>::stop_all().c(d!()).map(|_| None),
            Op::PushNode => Env::<P, S>::load_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_node().c(d!()))
                .map(|_| None),
            Op::PopNode => Env::<P, S>::load_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node().c(d!()))
                .map(|_| None),
            Op::Show => Env::<P, S>::load_cfg(self).c(d!()).map(|env| {
                env.show();
                None
            }),
            Op::ShowAll => Env::<P, S>::show_all().c(d!()).map(|_| None),
            Op::List => Env::<P, S>::list_all().c(d!()).map(|_| None),
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<P: NodePorts, S: NodeOptsGenerator<Node<P>>> {
    // the name of this env
    #[serde(flatten)]
    name: EnvName,

    // data path of this env
    #[serde(rename = "env_home_dir")]
    home: String,

    host_ip: String,

    #[serde(rename = "app_bin_path")]
    app_bin: String,

    app_extra_opts: String,

    #[serde(rename = "tendermint_bin_path")]
    tendermint_bin: String,

    tendermint_extra_opts: String,

    // seconds between two blocks
    #[serde(rename = "block_interval_in_seconds")]
    block_itv_secs: u8,

    #[serde(rename = "seed_nodes")]
    seeds: BTreeMap<NodeId, Node<P>>,

    #[serde(rename = "validator_or_full_nodes")]
    nodes: BTreeMap<NodeId, Node<P>>,

    // the latest/max id of current nodes
    next_node_id: NodeId,

    // the contents of `genesis.json` of all nodes
    #[serde(rename = "tendermint_genesis")]
    genesis: String,

    #[serde(rename = "node_options_generator")]
    node_opts_generator: S,

    custom_information: JsonValue,
}

impl<P: NodePorts, S: NodeOptsGenerator<Node<P>>> Env<P, S> {
    // - initilize a new env
    // - `genesis.json` will be created
    fn create(cfg: &EnvCfg, opts: &EnvOpts, s: S) -> Result<Env<P, S>> {
        let home = format!("{}/envs/{}", &*GLOBAL_BASE_DIR, &cfg.name);

        if opts.force_create {
            omit!(
                Env::<P, S>::load_cfg(cfg)
                    .c(d!())
                    .and_then(|env| env.destroy().c(d!()))
            );
            omit!(fs::remove_dir_all(&home));
        }

        if fs::metadata(&home).is_ok() {
            return Err(eg!("Another env with the same name exists!"));
        }

        let mut env = Env {
            name: cfg.name.clone(),
            home,
            host_ip: opts.host_ip.clone(),
            app_bin: opts.app_bin_path.clone(),
            app_extra_opts: opts.app_extra_opts.clone(),
            tendermint_bin: opts.tendermint_bin_path.clone(),
            tendermint_extra_opts: opts.tendermint_extra_opts.clone(),
            block_itv_secs: opts.block_itv_secs,
            nodes: Default::default(),
            seeds: Default::default(),
            next_node_id: Default::default(),
            genesis: Default::default(),
            node_opts_generator: s,
            custom_information: opts.custom_information.clone(),
        };

        fs::create_dir_all(&env.home).c(d!())?;

        macro_rules! add_initial_nodes {
            ($kind: tt) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, Kind::$kind).c(d!())?;
            }};
        }

        add_initial_nodes!(Seed);
        for _ in 0..opts.initial_validator_num {
            add_initial_nodes!(Node);
        }

        env.gen_genesis(&opts.app_state)
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None).c(d!()))
            .map(|_| env)
    }

    // start one or all nodes
    fn start(&mut self, n: Option<NodeId>) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.seeds
                .keys()
                .chain(self.nodes.keys())
                .copied()
                .collect()
        });

        self.update_peer_cfg()
            .c(d!())
            .and_then(|_| self.write_cfg().c(d!()))?;

        for i in ids.iter() {
            if let Some(n) = self.nodes.get_mut(i) {
                n.start(
                    &self.app_bin,
                    &self.app_extra_opts,
                    &self.tendermint_bin,
                    &self.tendermint_extra_opts,
                    &self.node_opts_generator,
                )
                .c(d!())?;
            } else if let Some(n) = self.seeds.get_mut(i) {
                n.start(
                    &self.app_bin,
                    &self.app_extra_opts,
                    &self.tendermint_bin,
                    &self.tendermint_extra_opts,
                    &self.node_opts_generator,
                )
                .c(d!())?;
            } else {
                return Err(eg!("not exist"));
            }
        }

        Ok(())
    }

    // start all existing ENVs
    fn start_all() -> Result<()> {
        for env in Self::get_all_envs().c(d!())?.iter() {
            Self::read_cfg(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .start(None)
                .c(d!())?;
        }
        Ok(())
    }

    // - stop all processes
    // - release all occupied ports
    fn stop(&self) -> Result<()> {
        self.nodes
            .values()
            .chain(self.seeds.values())
            .map(|n| n.stop().c(d!()))
            .collect::<Result<Vec<_>>>()
            .map(|_| ())
    }

    // stop all existing ENVs
    fn stop_all() -> Result<()> {
        for env in Self::get_all_envs().c(d!())?.iter() {
            Self::read_cfg(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .stop()
                .c(d!())?;
        }
        Ok(())
    }

    // destroy all nodes
    // - stop all running processes
    // - delete the data of every nodes
    fn destroy(&self) -> Result<()> {
        info_omit!(self.stop());
        sleep_ms!(10);

        for n in self.seeds.values().chain(self.nodes.values()) {
            n.clean().c(d!())?;
        }

        fs::remove_dir_all(&self.home).c(d!())
    }

    // destroy all existing ENVs
    fn destroy_all() -> Result<()> {
        for env in Self::get_all_envs().c(d!())?.iter() {
            Self::read_cfg(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .destroy()
                .c(d!())?;
        }
        fs::remove_dir_all(&*GLOBAL_BASE_DIR).c(d!())
    }

    // seed nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(&mut self) -> Result<()> {
        let id = self.next_node_id();
        let kind = Kind::Node;
        self.alloc_resources(id, kind)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start(Some(id)).c(d!()))
    }

    // the first node(validator) can not removed
    fn kick_node(&mut self) -> Result<()> {
        self.nodes
            .keys()
            .skip(1)
            .rev()
            .copied()
            .next()
            .c(d!())
            .and_then(|k| self.nodes.remove(&k).c(d!()))
            .and_then(|n| n.stop().c(d!()).and_then(|_| n.clean().c(d!())))
            .and_then(|_| self.write_cfg().c(d!()))
    }

    fn show(&self) {
        println!("{}", pnk!(serde_json::to_string_pretty(self)));
    }

    // show the details of all existing ENVs
    fn show_all() -> Result<()> {
        for (idx, env) in Self::get_all_envs().c(d!())?.iter().enumerate() {
            println!("\x1b[31;01m====== ENV No.{} ======\x1b[00m", idx);
            Self::read_cfg(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .show();
            println!();
        }
        Ok(())
    }

    // list the names of all existing ENVs
    fn list_all() -> Result<()> {
        let list = Self::get_all_envs().c(d!())?;

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

    // 1. allocate ports
    // 2. change configs: ports, seed address, etc.
    // 3. insert new node to the meta of env
    // 4. write new configs of tendermint to disk
    fn alloc_resources(&mut self, id: NodeId, kind: Kind) -> Result<()> {
        // 1.
        let ports = self.alloc_ports(&kind).c(d!())?;

        // 2.
        let home = format!("{}/{}", self.home, id);
        fs::create_dir_all(&home).c(d!())?;

        let cfg_path = format!("{}/config/config.toml", &home);
        let role_mark = match kind {
            Kind::Node => "node",
            Kind::Seed => "seed",
        };
        let mut cfg = fs::read_to_string(&cfg_path)
            .c(d!())
            .or_else(|_| {
                cmd::exec_output(&format!(
                    "{} init {} --home {}",
                    &self.tendermint_bin, role_mark, &home
                ))
                .c(d!())
                .and_then(|_| fs::read_to_string(&cfg_path).c(d!()))
            })
            .and_then(|c| c.parse::<Document>().c(d!()))?;

        cfg["proxy_app"] =
            toml_value(format!("tcp://{}:{}", &self.host_ip, ports.get_sys_abci()));

        #[cfg(all(target_os = "linux", feature = "unix_abstract_socket"))]
        {
            // Use 'unix abstract socket address', `man unix(7)` for more infomation.
            // A '@'-prefix is necessary for tendermint(written in go) to distinguish its type
            cfg["rpc"]["laddr"] =
                toml_value(format!("unix://@{}{}", rand::random::<u64>(), &self.name));
        }

        #[cfg(any(not(target_os = "linux"), not(feature = "unix_abstract_socket")))]
        {
            cfg["rpc"]["laddr"] =
                toml_value(format!("tcp://{}:{}", &self.host_ip, ports.get_sys_rpc()));
        }

        let mut arr = Array::new();
        arr.push("*");
        cfg["rpc"]["cors_allowed_origins"] = toml_value(arr);

        cfg["p2p"]["addr_book_strict"] = toml_value(false);
        cfg["p2p"]["allow_duplicate_ip"] = toml_value(true);
        cfg["p2p"]["persistent_peers_max_dial_period"] = toml_value("3s");
        cfg["p2p"]["send_rate"] = toml_value(64 * MB);
        cfg["p2p"]["recv_rate"] = toml_value(64 * MB);
        cfg["p2p"]["laddr"] =
            toml_value(format!("tcp://{}:{}", &self.host_ip, ports.get_sys_p2p()));

        cfg["consensus"]["timeout_propose"] = toml_value("16s");
        cfg["consensus"]["timeout_propose_delta"] = toml_value("100ms");
        cfg["consensus"]["timeout_prevote"] = toml_value("2s");
        cfg["consensus"]["timeout_prevote_delta"] = toml_value("100ms");
        cfg["consensus"]["timeout_precommit"] = toml_value("2s");
        cfg["consensus"]["timeout_precommit_delta"] = toml_value("100ms");
        cfg["consensus"]["timeout_commit"] =
            toml_value(self.block_itv_secs.to_string() + "s");
        cfg["consensus"]["skip_timeout_commit"] = toml_value(false);
        cfg["consensus"]["create_empty_blocks"] = toml_value(false);
        cfg["consensus"]["create_empty_blocks_interval"] = toml_value("30s");

        cfg["mempool"]["recheck"] = toml_value(false);

        cfg["moniker"] = toml_value(format!("{}-{}", &self.name, id));

        match kind {
            Kind::Node => {
                cfg["p2p"]["pex"] = toml_value(true);
                cfg["p2p"]["seed_mode"] = toml_value(false);
                cfg["p2p"]["max_num_inbound_peers"] = toml_value(40);
                cfg["p2p"]["max_num_outbound_peers"] = toml_value(10);
                cfg["mempool"]["broadcast"] = toml_value(true);
                cfg["mempool"]["size"] = toml_value(200_0000);
                cfg["mempool"]["max_txs_bytes"] = toml_value(5 * GB);
                cfg["tx_index"]["indexer"] = toml_value("kv");
                cfg["rpc"]["max_open_connections"] = toml_value(10_0000);
            }
            Kind::Seed => {
                cfg["p2p"]["pex"] = toml_value(true);
                cfg["p2p"]["seed_mode"] = toml_value(true);
                cfg["p2p"]["max_num_inbound_peers"] = toml_value(400);
                cfg["p2p"]["max_num_outbound_peers"] = toml_value(100);
                cfg["mempool"]["broadcast"] = toml_value(false);
                cfg["tx_index"]["indexer"] = toml_value("null");
            }
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
            home: format!("{}/{}", &self.home, id),
            kind,
            ports,
        };

        match kind {
            Kind::Node => self.nodes.insert(id, node),
            Kind::Seed => self.seeds.insert(id, node),
        };

        // 4.
        fs::write(cfg_path, cfg.to_string()).c(d!())
    }

    // global alloctor for ports
    fn alloc_ports(&self, node_kind: &Kind) -> Result<P> {
        let mut ports = P::default();
        let reserved_ports = P::reserved();

        let mut res = vec![];
        if matches!(node_kind, Kind::Node)
            && ENV_NAME_DEFAULT == self.name.as_ref()
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
        ports.set_all_ports(&res);

        Ok(ports)
    }

    fn update_peer_cfg(&self) -> Result<()> {
        for n in self.nodes.values() {
            let cfg_path = format!("{}/config/config.toml", &n.home);
            let mut cfg = fs::read_to_string(&cfg_path)
                .c(d!())
                .and_then(|c| c.parse::<Document>().c(d!()))?;
            cfg["p2p"]["seeds"] = toml_value(
                self.seeds
                    .values()
                    .map(|n| {
                        format!(
                            "{}@{}:{}",
                            &n.tm_id,
                            &self.host_ip,
                            n.ports.get_sys_p2p()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
            cfg["p2p"]["persistent_peers"] = toml_value(
                self.nodes
                    .values()
                    .filter(|peer| peer.id != n.id)
                    .map(|n| {
                        format!(
                            "{}@{}:{}",
                            &n.tm_id,
                            &self.host_ip,
                            n.ports.get_sys_p2p()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
            fs::write(cfg_path, cfg.to_string()).c(d!())?;
        }

        for n in self.seeds.values() {
            let cfg_path = format!("{}/config/config.toml", &n.home);
            let mut cfg = fs::read_to_string(&cfg_path)
                .c(d!())
                .and_then(|c| c.parse::<Document>().c(d!()))?;
            cfg["p2p"]["persistent_peers"] = toml_value(
                self.nodes
                    .values()
                    .filter(|peer| peer.id != n.id)
                    .map(|n| {
                        format!(
                            "{}@{}:{}",
                            &n.tm_id,
                            &self.host_ip,
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
    fn next_node_id(&mut self) -> NodeId {
        let ret = self.next_node_id;
        self.next_node_id += 1;
        ret
    }

    // Generate a new `genesis.json`
    // based on the collection of initial validators.
    fn gen_genesis(&mut self, app_state: &JsonValue) -> Result<()> {
        let tmp_id = NodeId::MAX;
        let tmp_home = format!("{}/{}", &self.home, tmp_id);

        let gen = |genesis_file: String| {
            self.nodes
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
                .and_then(|vs| serde_json::to_value(&vs).c(d!()))
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
                        .map(|mut g| {
                            g["validators"] = vs;
                            g["app_state"] = app_state.clone();
                            self.genesis = g.to_string();
                        })
                })
        };

        cmd::exec_output(&format!(
            "{} init validator --home {}",
            &self.tendermint_bin, &tmp_home
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

    // apply genesis to one/all nodes in the same env
    fn apply_genesis(&mut self, n: Option<NodeId>) -> Result<()> {
        let nodes = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.seeds
                .keys()
                .chain(self.nodes.keys())
                .copied()
                .collect()
        });

        for n in nodes.iter() {
            self.nodes
                .get(n)
                .or_else(|| self.seeds.get(n))
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
                            fs::write(genesis_path, &self.genesis).c(d!())
                        })
                })?;
        }

        Ok(())
    }

    fn get_all_envs() -> Result<Vec<EnvName>> {
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

    fn load_cfg(cfg: &EnvCfg) -> Result<Env<P, S>> {
        Self::read_cfg(&cfg.name).c(d!()).and_then(|env| match env {
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

    fn read_cfg(cfg_name: &EnvName) -> Result<Option<Env<P, S>>> {
        let p = format!("{}/envs/{}/config.json", &*GLOBAL_BASE_DIR, cfg_name);
        match fs::read_to_string(&p) {
            Ok(d) => Ok(serde_json::from_str(&d).c(d!())?),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(eg!(e)),
            },
        }
    }

    fn write_cfg(&self) -> Result<()> {
        serde_json::to_vec_pretty(self)
            .c(d!())
            .and_then(|d| fs::write(format!("{}/config.json", &self.home), d).c(d!()))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    id: NodeId,
    #[serde(rename = "tendermint_node_id")]
    tm_id: String,
    #[serde(rename = "node_home_dir")]
    pub home: String,
    kind: Kind,
    pub ports: P,
}

impl<P: NodePorts> Node<P> {
    // - start node
    // - collect results
    // - update meta
    fn start(
        &mut self,
        app_bin: &str,
        app_extra_opts: &str,
        tendermint_bin: &str,
        tendermint_extra_opts: &str,
        opts_generator: &impl NodeOptsGenerator<Node<P>>,
    ) -> Result<()> {
        self.stop().c(d!())?;
        match unsafe { unistd::fork() } {
            Ok(ForkResult::Child) => {
                let cmd = format!(
                    "nohup {tmbin} {tmopts} >{home}/tendermint.log 2>&1 & \
                     nohup {appbin} {appopts} >{home}/app.log 2>&1 &",
                    tmbin = tendermint_bin,
                    tmopts = opts_generator.tendermint_opts(self, tendermint_extra_opts),
                    appbin = app_bin,
                    appopts = opts_generator.app_opts(self, app_extra_opts),
                    home = &self.home,
                );
                pnk!(self.write_dev_log(&cmd));
                pnk!(exec_spawn(&cmd));
                exit(0);
            }
            Ok(_) => Ok(()),
            Err(_) => Err(eg!("fork failed!")),
        }
    }

    fn stop(&self) -> Result<()> {
        let cmd = format!(
            "for i in \
                $(ps ax -o pid,args \
                    | grep '{}' \
                    | grep -v 'grep' \
                    | grep -Eo '^ *[0-9]+' \
                    | sed 's/ //g' \
                ); \
             do kill -9 $i; done",
            &self.home
        );
        let outputs = cmd::exec_output(&cmd).c(d!())?;
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

    // - release all occupied ports
    // - remove all files related to this node
    fn clean(&self) -> Result<()> {
        for port in self.ports.get_all_ports().into_iter() {
            PortsCache::remove(port).c(d!())?;
        }
        fs::remove_dir_all(&self.home).c(d!())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
enum Kind {
    #[serde(rename = "ValidatorOrFull")]
    Node,
    Seed,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Op {
    Create(EnvOpts),
    Destroy,
    DestroyAll,
    Start,
    StartAll,
    Stop,
    StopAll,
    PushNode,
    PopNode,
    Show,
    ShowAll,
    List,
}

/// options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvOpts {
    /// default to '127.0.0.1'
    pub host_ip: String,

    /// seconds between two blocks
    pub block_itv_secs: u8,

    /// how many initial validators should be created,
    /// default to 4
    pub initial_validator_num: u8,

    pub app_bin_path: String,
    pub app_extra_opts: String,

    pub tendermint_bin_path: String,
    pub tendermint_extra_opts: String,

    pub force_create: bool,

    pub app_state: JsonValue,
    pub custom_information: JsonValue,
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
        info_omit!(ret);
        false
    }
}

fn check_port(port: u16) -> Result<()> {
    let check = |st: SockType| {
        let fd = socket(AddressFamily::Inet, st, SockFlag::empty(), None).c(d!())?;

        setsockopt(fd, sockopt::ReuseAddr, &true)
            .c(d!())
            .and_then(|_| setsockopt(fd, sockopt::ReusePort, &true).c(d!()))
            .and_then(|_| socket::bind(fd, &SockaddrIn::new(0, 0, 0, 0, port)).c(d!()))
            .and_then(|_| unistd::close(fd).c(d!()))
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
        format!("{}/DEV_ports_cache", &*GLOBAL_BASE_DIR)
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
