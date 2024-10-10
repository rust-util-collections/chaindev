use super::remote::Remote;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap, env, fmt, path::PathBuf, str::FromStr, sync::LazyLock,
    thread,
};

static DEFAULT_SSH_USER: LazyLock<String> =
    LazyLock::new(|| pnk!(env::var("USER"), "$USER not defined!"));

static DEFAULT_SSH_PRIVKEY_PATH: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
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
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostAddr {
    pub local: String,
    pub local_id: String,
    pub external: Option<String>,
}

impl HostAddr {
    #[inline(always)]
    pub fn connection_addr(&self) -> &str {
        self.external.as_deref().unwrap_or(&self.local)
    }

    /// Use the local ip to get better performance,
    /// if they are locating in the same local network
    pub fn connection_addr_x(&self, local_id: &str) -> &str {
        if !self.local_id.is_empty() && self.local_id == local_id {
            &self.local
        } else {
            self.connection_addr()
        }
    }

    #[inline(always)]
    pub fn host_id(&self) -> HostID {
        self.to_string()
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}",
            self.local,
            self.external.as_deref().unwrap_or_default()
        )
    }
}

impl FromStr for HostAddr {
    type Err = Box<dyn RucError>;
    fn from_str(s: &str) -> Result<Self> {
        let addrs = s.split('|').collect::<Vec<_>>();
        if addrs.is_empty() || addrs.len() > 2 {
            return Err(eg!());
        }

        let local = addrs[0].split('%').collect::<Vec<_>>();
        let (local_id, local) = if 1 == local.len() {
            ("".to_owned(), local[0].to_owned())
        } else if 2 == local.len() {
            (local[0].to_owned(), local[1].to_owned())
        } else {
            return Err(eg!());
        };

        let addr = if 1 == addrs.len() {
            HostAddr {
                local,
                local_id,
                external: None,
            }
        } else {
            HostAddr {
                local,
                local_id,
                external: Some(addrs[1].to_owned()),
            }
        };

        Ok(addr)
    }
}

pub type HostExpression = String;
pub type HostExpressionRef<'a> = &'a str;

type Weight = u64;
type WeightGuard = u8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    #[serde(flatten)]
    pub meta: HostMeta,

    // The weight used when allocating nodes
    pub(super) weight: Weight,

    // How many nodes have been created
    pub(super) node_cnt: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostMeta {
    // addr, addr_external
    pub addr: HostAddr,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub(super) ssh_local_seckeys: Vec<PathBuf>,
}

// #[derive(Debug, Clone)]
// pub(super) enum HostOS {
//     Linux,
//     MacOS,
//     FreeBSD,
//     Unknown(String),
// }

type HostMap = BTreeMap<HostID, Host>;

pub type HostID = String;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
///   remote_host_local_id%remote_host_local_addr|remote_host_external_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
///   ...,
///   ...,
///   remote_host_local_id%remote_host_local_addr|remote_host_external_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
///   ...,
/// "
pub fn param_parse_hosts(hosts: HostExpressionRef) -> Result<HostMap> {
    let hosts = hosts
        .trim_matches(|c| c == ' ' || c == '\t' || c == '\n')
        .split(',')
        .filter(|l| !l.is_empty())
        .map(|h| h.trim().split('#').collect::<Vec<_>>())
        .collect::<Vec<_>>();

    if hosts.iter().any(|h| h.is_empty()) || hosts.iter().any(|h| h.len() > 5) {
        return Err(eg!("invalid length"));
    }

    let mut hosts = hosts
        .into_iter()
        .map(|h| {
            if 1 == h.len() {
                HostAddr::from_str(h[0]).c(d!()).map(|addr| Host {
                    meta: HostMeta {
                        addr,
                        ssh_user: DEFAULT_SSH_USER.clone(),
                        ssh_port: 22,
                        ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 2 == h.len() {
                HostAddr::from_str(h[0]).c(d!()).map(|addr| Host {
                    meta: HostMeta {
                        addr,
                        ssh_user: h[1].to_owned(),
                        ssh_port: 22,
                        ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 3 == h.len() {
                HostAddr::from_str(h[0]).c(d!()).and_then(|addr| {
                    h[2].parse::<u16>().c(d!()).map(|p| Host {
                        meta: HostMeta {
                            addr,
                            ssh_user: h[1].to_owned(),
                            ssh_port: p,
                            ssh_local_seckeys: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                        },
                        weight: 0,
                        node_cnt: 0,
                    })
                })
            } else {
                HostAddr::from_str(h[0]).c(d!()).and_then(|addr| {
                    h[2].parse::<u16>().c(d!()).and_then(|p| {
                        h[3].parse::<WeightGuard>().c(d!()).map(|w| Host {
                            meta: HostMeta {
                                addr,
                                ssh_user: h[1].to_owned(),
                                ssh_port: p,
                                ssh_local_seckeys: alt!(
                                    5 == h.len(),
                                    vec![PathBuf::from(h[4])],
                                    DEFAULT_SSH_PRIVKEY_PATH.clone()
                                ),
                            },
                            weight: w as Weight,
                            node_cnt: 0,
                        })
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
        .map(|h| (h.meta.addr.host_id(), h))
        .collect::<BTreeMap<_, _>>();

    if ret.is_empty() {
        Err(eg!("No valid hosts found!"))
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn addr_parse() {
        let text = "a%10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local: "10.0.0.8".to_owned(),
                local_id: "a".to_owned(),
                external: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "%10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local: "10.0.0.8".to_owned(),
                local_id: "".to_owned(),
                external: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local: "10.0.0.8".to_owned(),
                local_id: "".to_owned(),
                external: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "a10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local: "a10.0.0.8".to_owned(),
                local_id: "".to_owned(),
                external: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );
    }
}
