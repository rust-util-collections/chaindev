pub mod hosts;
pub mod remote;

use ruc::*;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const ENV_NAME_DEFAULT: &str = "DEFAULT";

pub const MB: i64 = 1024 * 1024;
pub const GB: i64 = 1024 * MB;

pub type NodeID = u32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnvName {
    #[serde(rename = "env_name")]
    name: String,
}

impl Default for EnvName {
    fn default() -> Self {
        Self {
            name: ENV_NAME_DEFAULT.to_owned(),
        }
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.name)
    }
}

impl From<String> for EnvName {
    fn from(name: String) -> Self {
        Self { name }
    }
}

impl From<&str> for EnvName {
    fn from(n: &str) -> Self {
        Self { name: n.to_owned() }
    }
}

impl AsRef<str> for EnvName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

pub trait CustomOps:
    Clone + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    fn exec(&self, env_name: &EnvName) -> Result<()>;
}

impl CustomOps for () {
    fn exec(&self, _: &EnvName) -> Result<()> {
        Ok(())
    }
}

pub trait NodeCmdGenerator<N, E>:
    Clone + fmt::Debug + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    /// Return: whether the target node is running
    fn cmd_cnt_running(&self, node: &N, env_meta: &E) -> String;

    /// Return: the custom cmd to start the node
    fn cmd_for_start(&self, node: &N, env_meta: &E) -> String;

    /// Return: the custom cmd to stop the node
    fn cmd_for_stop(&self, node: &N, env_meta: &E, force: bool) -> String;

    /// Return: a `FnOnce` containing the full logic for the migration
    fn cmd_for_migrate(
        &self,
        _src_node: &N,
        _dst_node: &N,
        _env_meta: &E,
    ) -> impl FnOnce() -> Result<()> {
        || Err(eg!("Unimplemented yet !!"))
    }
}

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
