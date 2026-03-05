// Flow sketch: scan request -> probe engine -> raw findings
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// lua hooks are guest artists, not permanent band members.

use std::fs;
use std::path::Path;

use mlua::{Lua, LuaSerdeExt, Value};

use crate::error::{NProbeError, NProbeResult};
use crate::models::HostResult;

const DEFAULT_LUA_RULES: &str = include_str!("../../lua/default_rules.lua");

pub fn run(host: &HostResult, script_path: Option<&Path>) -> NProbeResult<Vec<String>> {
    let script = if let Some(path) = script_path {
        fs::read_to_string(path)?
    } else {
        DEFAULT_LUA_RULES.to_string()
    };

    let lua = Lua::new();
    lua.load(&script).set_name("nprobe_rules").exec()?;
    let analyze = lua
        .globals()
        .get::<mlua::Function>("analyze")
        .map_err(|_| NProbeError::Parse("lua script must define analyze(host)".to_string()))?;

    let host_value = lua.to_value(host)?;
    let result: Value = analyze.call(host_value)?;
    let mut findings = Vec::new();

    match result {
        Value::Nil => {}
        Value::String(msg) => findings.push(msg.to_str()?.to_string()),
        Value::Table(table) => {
            for item in table.sequence_values::<String>() {
                findings.push(item?);
            }
        }
        _ => {
            return Err(NProbeError::Parse(
                "analyze(host) must return string, table, or nil".to_string(),
            ));
        }
    }

    Ok(findings)
}
