use super::remote::Remote;
use once_cell::sync::Lazy;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, path::PathBuf, str::FromStr, thread};

static DEFAULT_SSH_USER: Lazy<String> =
    Lazy::new(|| pnk!(env::var("USER"), "$USER not defined!"));

static DEFAULT_SSH_PRIVKEY_PATH: Lazy<Vec<PathBuf>> = Lazy::new(|| {
    let home = env::var("HOME").expect("$HOME not defined!");

    let ed25519_key_path = PathBuf::from(format!("{}/.ssh/id_ed25519", &home));
    let rsa_key_path = PathBuf::from(home + "{}/.ssh/id_rsa");

    let mut ret = vec![];

    if ed25519_key_path.exists() {
        ret.push(ed25519_key_path);
    } else if rsa_key_path.exists() {
        ret.push(rsa_key_path);
    };

    ret
});

// ip, domain, ...
pub type HostAddr = String;
pub type HostAddrRef<'a> = &'a str;
pub type HostExpression = String;
pub type HostExpressionRef<'a> = &'a str;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    pub meta: HostMeta,

    // The weight used when allocating nodes
    pub(super) weight: u64,

    // How many nodes have been created
    pub(super) node_cnt: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostMeta {
    pub addr: HostAddr,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub(super) ssh_local_seckeys: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub(super) enum HostOS {
    Linux,
    MacOS,
    FreeBSD,
    Unknown(String),
}

type HostMap = BTreeMap<HostAddr, Host>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hosts(HostMap);

impl FromStr for Hosts {
    type Err = Box<dyn RucError>;
    fn from_str(s: &str) -> Result<Self> {
        param_parse_hosts(s).c(d!()).map(Hosts)
    }
}

impl From<&str> for Hosts {
    fn from(s: &str) -> Self {
        pnk!(Self::from_str(s))
    }
}

impl From<&String> for Hosts {
    fn from(s: &String) -> Self {
        pnk!(Self::from_str(s.as_str()))
    }
}

impl From<String> for Hosts {
    fn from(s: String) -> Self {
        pnk!(Self::from_str(s.as_str()))
    }
}

impl AsRef<HostMap> for Hosts {
    fn as_ref(&self) -> &HostMap {
        &self.0
    }
}

impl AsMut<HostMap> for Hosts {
    fn as_mut(&mut self) -> &mut HostMap {
        &mut self.0
    }
}

/// "
///   ssh_remote_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
///   ...,
///   ...,
///   ssh_remote_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
///   ...,
/// "
pub fn param_parse_hosts(hosts: HostExpressionRef) -> Result<HostMap> {
    let hosts = hosts
        .trim_matches(|c| c == ' ' || c == '\t')
        .split(',')
        .map(|h| h.split('#').collect::<Vec<_>>())
        .collect::<Vec<_>>();

    if hosts.iter().any(|h| h.is_empty()) || hosts.iter().any(|h| h.len() > 5) {
        return Err(eg!("invalid length"));
    }

    let mut hosts = hosts
        .into_iter()
        .map(|h| {
            if 1 == h.len() {
                Ok(Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: DEFAULT_SSH_USER.clone(),
                        ssh_port: 22,
                        ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 2 == h.len() {
                Ok(Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: h[1].to_owned(),
                        ssh_port: 22,
                        ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 3 == h.len() {
                h[2].parse::<u16>().c(d!()).map(|p| Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: h[1].to_owned(),
                        ssh_port: p,
                        ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else {
                h[2].parse::<u16>().c(d!()).and_then(|p| {
                    h[3].parse::<u64>().c(d!()).map(|w| Host {
                        meta: HostMeta {
                            addr: h[0].to_owned(),
                            ssh_user: h[1].to_owned(),
                            ssh_port: p,
                            ssh_local_seckeys: alt!(
                                5 == h.len(),
                                vec![PathBuf::from(h[4])],
                                DEFAULT_SSH_PRIVKEY_PATH.clone()
                            ),
                        },
                        weight: w,
                        node_cnt: 0,
                    })
                })
            }
        })
        .collect::<Result<Vec<Host>>>()
        .c(d!())?;

    if hosts.iter().any(|h| 0 == h.weight) {
        hosts = thread::scope(|s| {
            hosts
                .into_iter()
                .map(|mut h| {
                    s.spawn(|| {
                        h.weight = Remote::from(&h.meta).get_hosts_weight().c(d!())?;
                        Ok(h)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .collect::<Result<Vec<_>>>()
        })
        .c(d!())?;
    }

    let ret = hosts
        .into_iter()
        .map(|h| (h.meta.addr.clone(), h))
        .collect::<BTreeMap<_, _>>();

    if ret.is_empty() {
        Err(eg!("No valid hosts found!"))
    } else {
        Ok(ret)
    }
}
