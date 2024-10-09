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
