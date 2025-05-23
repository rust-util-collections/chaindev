use super::remote::Remote;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap, env, fmt, path::PathBuf, str::FromStr, sync::LazyLock,
    thread,
};

// ip, domain, ...
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostAddr {
    pub local_ip: String,
    #[serde(default = "default_local_network_id")]
    pub local_network_id: String,
    pub ext_ip: Option<String>,
}

fn default_local_network_id() -> String {
    "default_mlm_mmm_lqm_qmzl_9527".to_owned()
}

impl HostAddr {
    #[inline(always)]
    pub fn connection_addr(&self) -> &str {
        self.ext_ip.as_deref().unwrap_or(&self.local_ip)
    }

    /// Use the local ip to get better performance,
    /// if they are locating in the same local network
    pub fn connection_addr_x(&self, local_network_id: &str) -> &str {
        if self.local_network_id == local_network_id {
            &self.local_ip
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
            "{}{}{}",
            self.local_ip,
            alt!(self.ext_ip.is_some(), "|", ""),
            self.ext_ip.as_deref().unwrap_or_default()
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

        let local_info = addrs[0].split('%').collect::<Vec<_>>();
        let (local_network_id, local_ip) = if 1 == local_info.len() {
            (default_local_network_id(), local_info[0].to_owned())
        } else if 2 == local_info.len() {
            (local_info[0].to_owned(), local_info[1].to_owned())
        } else {
            return Err(eg!());
        };

        let addr = if 1 == addrs.len() {
            HostAddr {
                local_ip,
                local_network_id,
                ext_ip: None,
            }
        } else {
            HostAddr {
                local_ip,
                local_network_id,
                ext_ip: Some(addrs[1].to_owned()),
            }
        };

        Ok(addr)
    }
}

pub type HostExpression = String;
pub type HostExpressionRef<'a> = &'a str;

pub type Weight = i64;
type WeightGuard = i16;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    #[serde(flatten)]
    pub meta: HostMeta,

    // The weight used when allocating nodes
    #[serde(default)]
    pub weight: Weight,

    // How many nodes have been created
    #[serde(default)]
    pub node_cnt: u64,
}

impl Host {
    #[inline(always)]
    pub fn host_id(&self) -> HostID {
        self.meta.host_id()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostMeta {
    // addr, addr_ext_ip
    #[serde(flatten)]
    pub addr: HostAddr,
    #[serde(default)]
    pub ssh_user: String,
    #[serde(default)]
    pub ssh_port: u16,
    #[serde(rename = "ssh_private_key_path")]
    #[serde(default)]
    pub ssh_sk_path: PathBuf,
}

impl HostMeta {
    #[inline(always)]
    pub fn host_id(&self) -> HostID {
        self.addr.host_id()
    }
}

fn default_ssh_user() -> String {
    static SSH_USER: LazyLock<String> =
        LazyLock::new(|| pnk!(env::var("USER"), "$USER not defined!"));

    (*SSH_USER).clone()
}

#[inline(always)]
fn default_ssh_port() -> u16 {
    22
}

fn default_ssh_sk_path() -> Option<PathBuf> {
    static SSH_SECKEYS: LazyLock<PathBuf> = LazyLock::new(|| {
        let home = env::var("HOME").expect("$HOME not defined!");

        let ed25519_key_path = PathBuf::from(format!("{}/.ssh/id_ed25519", &home));
        let rsa_key_path = PathBuf::from(home + "{}/.ssh/id_rsa");

        if ed25519_key_path.exists() {
            ed25519_key_path
        } else if rsa_key_path.exists() {
            rsa_key_path
        } else {
            PathBuf::new()
        }
    });

    if (*SSH_SECKEYS).as_os_str().is_empty() {
        None
    } else {
        Some((*SSH_SECKEYS).clone())
    }
}

// #[derive(Debug, Clone)]
// pub enum HostOS {
//     Linux,
//     MacOS,
//     FreeBSD,
//     Unknown(String),
// }

type HostMap = BTreeMap<HostID, Host>;

pub type HostID = String;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hosts(HostMap);

impl Hosts {
    #[inline(always)]
    pub fn from_json_cfg(s: &[u8]) -> Result<Self> {
        let mut cfg = serde_json::from_slice::<HostsJsonCfg>(s).c(d!())?;

        for h in cfg.hosts.iter_mut() {
            if 0 == h.weight {
                if let Some(w) = cfg.fallback_weight.as_ref() {
                    h.weight = (*w) as Weight;
                } else {
                    h.weight = Remote::from(&h.meta).get_hosts_weight().c(d!())?;
                }
            }
            if h.meta.ssh_user.is_empty() {
                if let Some(user) = cfg.fallback_ssh_user.as_ref() {
                    h.meta.ssh_user = user.to_owned();
                } else {
                    h.meta.ssh_user = default_ssh_user();
                }
            }
            if 0 == h.meta.ssh_port {
                if let Some(port) = cfg.fallback_ssh_port {
                    h.meta.ssh_port = port;
                } else {
                    h.meta.ssh_port = default_ssh_port();
                }
            }
            if h.meta.ssh_sk_path.as_os_str().is_empty() {
                if let Some(key) = cfg.fallback_ssh_sk_path.as_ref() {
                    h.meta.ssh_sk_path = key.clone();
                } else {
                    h.meta.ssh_sk_path = default_ssh_sk_path().c(d!())?;
                }
            }
        }

        let mut hosts = cfg.hosts;

        let hosts = if hosts.iter().any(|h| 0 == h.weight) {
            // Use chunks to avoid resource overload
            for hosts in hosts.chunks_mut(24) {
                thread::scope(|s| {
                    hosts
                        .iter_mut()
                        .map(|h| {
                            h.node_cnt = 0;
                            s.spawn(|| {
                                if 0 == h.weight {
                                    h.weight = Remote::from(&h.meta)
                                        .get_hosts_weight()
                                        .c(d!())?;
                                }
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
            hosts
                .into_iter()
                .map(|h| (h.meta.addr.host_id(), h))
                .collect()
        } else {
            hosts
                .into_iter()
                .map(|mut h| {
                    h.node_cnt = 0;
                    (h.meta.addr.host_id(), h)
                })
                .collect()
        };

        Ok(Hosts(hosts))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HostsJsonCfg {
    hosts: Vec<Host>,
    fallback_weight: Option<WeightGuard>,
    fallback_ssh_user: Option<String>,
    fallback_ssh_port: Option<u16>,
    fallback_ssh_sk_path: Option<PathBuf>,
}

impl HostsJsonCfg {
    #[cfg(test)]
    fn example() -> Self {
        let hosts = vec![
            Host {
                meta: HostMeta {
                    addr: HostAddr {
                        local_ip: "10.0.0.2".to_owned(),
                        local_network_id: default_local_network_id(),
                        ext_ip: Some("8.8.8.8".to_owned()),
                    },
                    ssh_user: "alice".to_owned(),
                    ssh_port: 2222,
                    ssh_sk_path: PathBuf::from("/home/fh/alice/.ssh/id_rsa"),
                },
                weight: 8,
                node_cnt: 0,
            },
            Host {
                meta: HostMeta {
                    addr: HostAddr {
                        local_ip: "10.0.0.3".to_owned(),
                        local_network_id: default_local_network_id(),
                        ext_ip: None,
                    },
                    ssh_user: String::new(),
                    ssh_port: u16::default(),
                    ssh_sk_path: PathBuf::new(),
                },
                weight: 4,
                node_cnt: 0,
            },
            Host {
                meta: HostMeta {
                    addr: HostAddr {
                        local_ip: "10.0.0.4".to_owned(),
                        local_network_id: default_local_network_id(),
                        ext_ip: Some("8.8.4.4".to_owned()),
                    },
                    ssh_user: "jack".to_owned(),
                    ssh_port: 0,
                    ssh_sk_path: PathBuf::from("/home/jack/.ssh/id_ed25519"),
                },
                weight: 0,
                node_cnt: 0,
            },
        ];

        Self {
            hosts,
            fallback_weight: Some(32),
            fallback_ssh_user: Some("bob".to_owned()),
            fallback_ssh_port: Some(22),
            fallback_ssh_sk_path: Some(PathBuf::from("/home/bob/.ssh/id_ed25519")),
        }
    }

    // # Example
    //
    // ```json
    // {
    //   "fallback_ssh_port": 22,
    //   "fallback_ssh_sk_path": "/home/bob/.ssh/id_ed25519",
    //   "fallback_ssh_user": "bob",
    //   "fallback_weight": 32,
    //   "hosts": [
    //     {
    //       "ext_ip": "8.8.8.8",
    //       "local_ip": "10.0.0.2",
    //       "ssh_port": 2222,
    //       "ssh_private_key_path": "/home/fh/alice/.ssh/id_rsa",
    //       "ssh_user": "alice",
    //       "weight": 8
    //     },
    //     {
    //       "local_ip": "10.0.0.3",
    //       "weight": 4
    //     },
    //     {
    //       "ext_ip": "8.8.4.4",
    //       "local_ip": "10.0.0.4",
    //       "ssh_private_key_path": "/home/jack/.ssh/id_ed25519",
    //       "ssh_user": "jack"
    //     }
    //   ]
    // }
    // ```
    #[cfg(test)]
    fn json_example() -> String {
        let mut v = serde_json::to_value(Self::example()).unwrap();
        v["hosts"].as_array_mut().unwrap().iter_mut().for_each(|h| {
            let hdr = h.as_object_mut().unwrap();
            hdr.remove("node_cnt");
            if 0 == hdr["weight"].as_u64().unwrap() {
                hdr.remove("weight");
            }
            if hdr["ssh_user"].as_str().unwrap().is_empty() {
                hdr.remove("ssh_user");
            }
            if 0 == hdr["ssh_port"].as_u64().unwrap() {
                hdr.remove("ssh_port");
            }
            if hdr["ssh_private_key_path"].as_str().unwrap().is_empty() {
                hdr.remove("ssh_private_key_path");
            }
            if hdr["local_network_id"].as_str().unwrap().is_empty() {
                hdr.remove("local_network_id");
            }
            if hdr["ext_ip"].as_null().is_some() {
                hdr.remove("ext_ip");
            }
        });
        serde_json::to_string_pretty(&v).unwrap()
    }
}

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
///   remote_host_local_network_id%remote_host_local_addr|remote_host_ext_ip_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
///   ...,
///   ...,
///   remote_host_local_network_id%remote_host_local_addr|remote_host_ext_ip_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,
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

    // fix me !!
    let default_ssh_sk_path = default_ssh_sk_path().c(d!())?;

    let mut hosts = hosts
        .into_iter()
        .map(|h| {
            if 1 == h.len() {
                HostAddr::from_str(h[0]).c(d!()).map(|addr| Host {
                    meta: HostMeta {
                        addr,
                        ssh_user: default_ssh_user(),
                        ssh_port: default_ssh_port(),
                        ssh_sk_path: default_ssh_sk_path.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 2 == h.len() {
                HostAddr::from_str(h[0]).c(d!()).map(|addr| Host {
                    meta: HostMeta {
                        addr,
                        ssh_user: h[1].to_owned(),
                        ssh_port: default_ssh_port(),
                        ssh_sk_path: default_ssh_sk_path.clone(),
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
                            ssh_sk_path: default_ssh_sk_path.clone(),
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
                                ssh_sk_path: alt!(
                                    5 == h.len(),
                                    PathBuf::from(h[4]),
                                    default_ssh_sk_path.clone()
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
        // Use chunks to avoid resource overload
        for hosts in hosts.chunks_mut(24) {
            thread::scope(|s| {
                hosts
                    .iter_mut()
                    .map(|h| {
                        s.spawn(|| {
                            if 0 == h.weight {
                                h.weight =
                                    Remote::from(&h.meta).get_hosts_weight().c(d!())?;
                            }
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
                local_ip: "10.0.0.8".to_owned(),
                local_network_id: "a".to_owned(),
                ext_ip: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "%10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local_ip: "10.0.0.8".to_owned(),
                local_network_id: "".to_owned(),
                ext_ip: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local_ip: "10.0.0.8".to_owned(),
                local_network_id: default_local_network_id(),
                ext_ip: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );

        let text = "a10.0.0.8|8.8.8.8";
        assert_eq!(
            HostAddr {
                local_ip: "a10.0.0.8".to_owned(),
                local_network_id: default_local_network_id(),
                ext_ip: Some("8.8.8.8".to_owned())
            },
            HostAddr::from_str(text).unwrap()
        );
    }

    #[test]
    fn cfg_json_example() {
        println!("\n{}", HostsJsonCfg::json_example());
    }
}
