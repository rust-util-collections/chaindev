use crate::{
    check_errlist,
    common::hosts::{Host, HostMeta, Hosts, Weight},
};
use ruc::{ssh, *};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use std::{fs, sync::Mutex, thread};

pub struct Remote<'a> {
    inner: ssh::RemoteHost<'a>,
}

impl<'a> From<&'a HostMeta> for Remote<'a> {
    fn from(h: &'a HostMeta) -> Self {
        Remote {
            inner: ssh::RemoteHost {
                addr: h.addr.connection_addr(),
                user: &h.ssh_user,
                port: h.ssh_port,
                local_sk: h.ssh_sk_path.as_path(),
            },
        }
    }
}

impl<'a> From<&'a Host> for Remote<'a> {
    fn from(h: &'a Host) -> Self {
        Self::from(&h.meta)
    }
}

impl Remote<'_> {
    // Execute a cmd on a remote host and get its outputs
    pub fn exec_cmd(&self, cmd: &str) -> Result<String> {
        let cmd = format!("ulimit -n 100000 >/dev/null 2>&1;{}", cmd);
        self.inner
            .exec_cmd(&cmd)
            .c(d!(cmd))
            .map(|c| String::from_utf8_lossy(&c).into_owned())
    }

    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        self.inner
            .read_file(path)
            .c(d!())
            .map(|c| String::from_utf8_lossy(&c).into_owned())
    }

    pub fn get_file<LP: AsRef<Path>, RP: AsRef<Path>>(
        &self,
        remote_path: RP,
        local_path: LP,
    ) -> Result<()> {
        self.inner.get_file(remote_path, local_path).c(d!())
    }

    /// Return: (the local path of tgz, the name of tgz)
    pub fn get_tgz_from_host(
        &self,
        absolute_path: &str,
        local_base_dir: Option<&str>,
    ) -> Result<String> {
        let local_base_dir = local_base_dir.unwrap_or("/tmp");

        let tgz_name = generate_name_from_path(absolute_path);
        let tgzcmd = format!("cd /tmp && tar -zcf {} {}", &tgz_name, absolute_path);

        self.exec_cmd(&tgzcmd).c(d!()).and_then(|_| {
            let remote_tgz_path = format!("/tmp/{}", &tgz_name);
            let local_path = format!("{}/{}", local_base_dir, tgz_name);
            self.get_file(remote_tgz_path, &local_path)
                .c(d!())
                .map(|_| local_path)
        })
    }

    pub fn replace_file<P: AsRef<Path>>(
        &self,
        remote_path: P,
        contents: &[u8],
    ) -> Result<()> {
        self.inner.replace_file(remote_path, contents).c(d!())
    }

    pub fn append_file<P: AsRef<Path>>(
        &self,
        remote_path: P,
        contents: &[u8],
    ) -> Result<()> {
        self.inner.append_file(remote_path, contents).c(d!())
    }

    pub fn put_file<LP: AsRef<Path>, RP: AsRef<Path>>(
        &self,
        local_path: LP,
        remote_path: RP,
    ) -> Result<()> {
        self.inner.put_file(local_path, remote_path).c(d!())
    }

    pub fn file_is_dir<P: AsRef<str>>(&self, remote_path: P) -> Result<bool> {
        self.exec_cmd(&format!(
            r"\ls -ld {} | grep -o '^.'",
            &remote_path.as_ref()
        ))
        .c(d!())
        .map(|file_mark| "d" == file_mark.trim())
    }

    pub fn get_occupied_ports(&self) -> Result<BTreeSet<u16>> {
        self.exec_cmd(
            r#"if [[ "Linux" = `uname -s` ]]; then ss -na | sed 's/ \+/ /g' | cut -d ' ' -f 5 | grep -o '[0-9]\+$'; elif [[ "Darwin" = `uname -s` ]]; then lsof -nP -i TCP | grep -o ':[0-9]\+[ -]'; else exit 1; fi"#,
        )
        .c(d!())
        .map(|s| {
            s.lines()
                .map(|l| l.trim_matches(|c| c == ':' || c == '-' || c == ' '))
                .filter(|p| !p.is_empty())
                .flat_map(|p| p.trim().parse::<u16>().ok())
                .collect::<BTreeSet<u16>>()
        })
    }

    pub fn get_hosts_weight(&self) -> Result<Weight> {
        let cpunum = self
            .exec_cmd(
            r#"if [[ "Linux" = `uname -s` ]]; then nproc; elif [[ "Darwin" = `uname -s` ]]; then sysctl -a | grep 'machdep.cpu.core_count' | grep -o '[0-9]\+$'; else exit 1; fi"#,
                )
            .c(d!())?
            .trim()
            .parse::<Weight>()
            .c(d!())?;

        // let bogomips = self
        //     .exec_cmd(
        //     r#"if [[ "Linux" = `uname -s` ]]; then grep bogomips /proc/cpuinfo | head -1 | sed 's/ //g' | cut -d ':' -f 2; elif [[ "Darwin" = `uname -s` ]]; then echo 4000.0; else exit 1; fi"#)
        //     .c(d!())?
        //     .trim()
        //     .parse::<f32>()
        //     .c(d!())? as u64;
        // Ok(cpunum.saturating_mul(bogomips))

        Ok(cpunum)
    }

    // pub fn hosts_os(&self) -> Result<HostOS> {
    //     let os = self.exec_cmd("uname -s").c(d!())?;
    //     let os = match os.trim() {
    //         "Linux" => HostOS::Linux,
    //         "Darwin" => HostOS::MacOS,
    //         "FreeBSD" => HostOS::FreeBSD,
    //         _ => HostOS::Unknown(os),
    //     };
    //     Ok(os)
    // }

    // fn get_local_privkey(&self) -> Result<String> {
    //     fs::read_to_string(self.ssh_local_privkey).c(d!())
    // }

    // fn port_is_free(&self, port: u16) -> bool {
    //     let occupied = pnk!(self.get_occupied_ports());
    //     !occupied.contains(&port)
    // }
}

/// Put a local file to some hosts
pub fn put_file_to_hosts(
    hosts: &Hosts,
    local_path: &str,
    remote_path: Option<&str>,
) -> Result<()> {
    let remote_path = remote_path.unwrap_or(local_path);

    // Use chunks to avoid resource overload
    for hosts in hosts.as_ref().values().collect::<Vec<_>>().chunks(12) {
        let errlist = thread::scope(|s| {
            hosts
                .iter()
                .map(|h| {
                    s.spawn(move || {
                        let remote = Remote::from(*h);
                        remote.put_file(local_path, remote_path).c(d!())
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

    Ok(())
}

/// Get a remote file from some hosts
pub fn get_file_from_hosts(
    hosts: &Hosts,
    remote_path: &str,
    local_base_dir: Option<&str>,
) -> Result<()> {
    let local_base_dir = local_base_dir.unwrap_or("/tmp");
    let remote_path = PathBuf::from(remote_path);
    let remote_file = remote_path.file_name().c(d!())?.to_str().c(d!())?;
    let remote_path = &remote_path;

    let mut errlist = vec![];

    // Use chunks to avoid resource overload
    for hosts in hosts.as_ref().values().collect::<Vec<_>>().chunks(12) {
        let mut local_paths = vec![];

        thread::scope(|s| {
            hosts
                .iter()
                .map(|h| {
                    let local_path =
                        format!("{}/{}_{}", local_base_dir, &h.meta.addr, remote_file);
                    s.spawn(move || {
                        let remote = Remote::from(*h);
                        remote
                            .get_file(remote_path, &local_path)
                            .c(d!())
                            .map(|_| (h.host_id(), local_path))
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .map(|lp| {
                    lp.map(|lp| {
                        local_paths.push(lp);
                    })
                })
                .for_each(|t| {
                    if let Err(e) = t {
                        errlist.push(e);
                    }
                });
        });

        // Print good resp at first,
        local_paths.sort_by(|a, b| a.0.cmp(&b.0));
        local_paths.into_iter().for_each(|(h, p)| {
            println!("HOST-[{h}] The file has been put at:\n\t{p}");
        });
    }

    check_errlist!(errlist)
}

/// Execute some commands or a script on some hosts
pub fn exec_cmds_on_hosts(
    hosts: &Hosts,
    cmd: Option<&str>,
    script_path: Option<&str>,
) -> Result<()> {
    static LK: Mutex<()> = Mutex::new(());

    let mut errlist = vec![];

    if let Some(cmd) = cmd {
        // Use chunks to avoid resource overload
        for hosts in hosts.as_ref().values().collect::<Vec<_>>().chunks(24) {
            thread::scope(|s| {
                hosts
                    .iter()
                    .map(|h| {
                        s.spawn(move || {
                            let remote = Remote::from(*h);
                            remote.exec_cmd(cmd).c(d!(&h.meta.addr)).map(|outputs| {
                                let lk = LK.lock();
                                println!("== HOST: {} ==\n{}", &h.meta.addr, outputs);
                                drop(lk);
                            })
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
    } else if let Some(sp) = script_path {
        let tmp_script_path = format!("/tmp/._{}", rand::random::<u64>());
        let cmd = format!("bash {}", tmp_script_path);

        let script = fs::read_to_string(sp).c(d!())?;
        let script =
            format!("{} && rm -f {}", script.trim_end(), tmp_script_path).into_bytes();

        // Use chunks to avoid resource overload
        for hosts in hosts.as_ref().values().collect::<Vec<_>>().chunks(12) {
            thread::scope(|s| {
                hosts
                    .iter()
                    .map(|h| {
                        let remote = Remote::from(*h);
                        let cmd = &cmd;
                        let script = &script;
                        let tmp_script_path = &tmp_script_path;
                        s.spawn(move || {
                            remote
                                .replace_file(tmp_script_path, script)
                                .c(d!())
                                .and_then(|_| {
                                    info!(remote.exec_cmd(cmd), &h.meta.addr).map(
                                        |outputs| {
                                            let lk = LK.lock();
                                            println!(
                                                "== HOST: {} ==\n{}",
                                                &h.meta.addr, outputs
                                            );
                                            drop(lk);
                                        },
                                    )
                                })
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
    } else {
        Err(eg!("neither `cmd` nor `script_path` has value!"))
    }
}

pub(super) fn generate_name_from_path(path: &str) -> String {
    path.replace('/', "_")
}
