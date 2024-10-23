use crate::{
    beacon_based::ddev::{Env, EnvMeta, Node, NodeCmdGenerator, NodePorts},
    check_errlist,
    common::remote::Remote,
    NodeID,
};
use ruc::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{fmt, thread};

pub fn collect_files_from_nodes<C, P, S>(
    env: &Env<C, P, S>,
    ids: Option<&[NodeID]>,
    files: &[&str], // file paths relative to the node home
    local_base_dir: Option<&str>,
) -> Result<()>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    if let Some(ids) = ids {
        for id in ids.iter() {
            if env
                .meta
                .nodes
                .get(id)
                .or_else(|| env.meta.fuhrers.get(id))
                .is_none()
            {
                return Err(eg!("The node(id: {}) does not exist!", id));
            }
        }
    }

    let local_base_dir = local_base_dir.unwrap_or("/tmp");

    let mut errlist = vec![];

    // Use chunks to avoid resource overload
    for (idx, nodes) in env
        .meta
        .fuhrers
        .values()
        .chain(env.meta.nodes.values())
        .filter(|n| ids.map(|ids| ids.contains(&n.id)).unwrap_or(true))
        .collect::<Vec<_>>()
        .chunks(12)
        .enumerate()
    {
        let mut path_map = BTreeMap::new();

        thread::scope(|s| {
            nodes
                .iter()
                .flat_map(|n| {
                    files.iter().map(|f| {
                        (
                            n.host.clone(),
                            *f,
                            format!("{}/{}", &n.home, f),
                            format!("N{}_{}_{}", n.id, n.kind, f.replace('/', "_")),
                        )
                    })
                })
                .map(|(host, relative_path, remote_path, remote_file)| {
                    let local_path = format!(
                        "{}/{}.{{{}}}",
                        local_base_dir,
                        remote_file,
                        host.addr.connection_addr()
                    );
                    s.spawn(move || {
                        let remote = Remote::from(&host);
                        remote
                            .get_file(remote_path, &local_path)
                            .c(d!())
                            .map(|_| (relative_path, local_path))
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .for_each(|t| match t {
                    Ok((f, lp)) => {
                        path_map.entry(f).or_insert_with(Vec::new).push(lp);
                    }
                    Err(e) => {
                        errlist.push(e);
                    }
                });
        });

        // Print good resp at first,
        path_map.into_iter().for_each(|(f, mut paths)| {
            println!("[Chunk {idx}] Files of the '{}' are stored at:", f);
            paths.sort();
            paths.iter().for_each(|p| {
                println!("\t- {}", p);
            });
        });
    }

    // Then pop err msg
    check_errlist!(errlist)
}

pub fn collect_tgz_from_nodes<'a, C, P, S>(
    env: &'a Env<C, P, S>,
    ids: Option<&[NodeID]>,
    paths: &'a [&'a str], // paths relative to the node home
    local_base_dir: Option<&'a str>,
) -> Result<()>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'x> Deserialize<'x>,
    P: NodePorts,
    S: NodeCmdGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    if let Some(ids) = ids {
        for id in ids.iter() {
            if env
                .meta
                .nodes
                .get(id)
                .or_else(|| env.meta.fuhrers.get(id))
                .is_none()
            {
                return Err(eg!("The node(id: {}) does not exist!", id));
            }
        }
    }

    let local_base_dir = local_base_dir.unwrap_or("/tmp");

    let mut errlist = vec![];

    // Use chunks to avoid resource overload
    for (idx, nodes) in env
        .meta
        .fuhrers
        .values()
        .chain(env.meta.nodes.values())
        .filter(|n| ids.map(|ids| ids.contains(&n.id)).unwrap_or(true))
        .collect::<Vec<_>>()
        .chunks(12)
        .enumerate()
    {
        let mut path_map = BTreeMap::new();

        thread::scope(|s| {
            nodes
                .iter()
                .flat_map(|n| {
                    paths.iter().map(|path| {
                        (
                            n.host.clone(),
                            *path,
                            format!("{}/{}", &n.home, path),
                            format!(
                                "N{}_{}_{}.tgz",
                                n.id,
                                n.kind,
                                path.replace('/', "_")
                            ),
                        )
                    })
                })
                .map(|(host, relative_path, remote_path, tgz_name)| {
                    let tgzcmd =
                        format!("cd /tmp && tar -zcf {} {}", &tgz_name, &remote_path);
                    let remote_tgz_path = format!("/tmp/{}", tgz_name);
                    let local_path = format!(
                        "{}/{}.{{{}}}",
                        local_base_dir,
                        &tgz_name,
                        host.addr.connection_addr()
                    );
                    s.spawn(move || {
                        let remote = Remote::from(&host);
                        remote
                            .exec_cmd(&tgzcmd)
                            .c(d!())
                            .and_then(|_| {
                                remote.get_file(remote_tgz_path, &local_path).c(d!())
                            })
                            .map(|_| (relative_path, local_path))
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .for_each(|t| match t {
                    Ok((f, lp)) => {
                        path_map.entry(f).or_insert_with(Vec::new).push(lp);
                    }
                    Err(e) => {
                        errlist.push(e);
                    }
                });
        });

        // Print good resp at first,
        path_map.into_iter().for_each(|(f, mut paths)| {
            println!("[Chunk {idx}] Tar packages of the '{}' are stored at:", f);
            paths.sort();
            paths.iter().for_each(|p| {
                println!("\t- {}", p);
            });
        });
    }

    // Then pop err msg
    check_errlist!(errlist)
}
