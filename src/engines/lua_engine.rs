use std::fs;
use std::path::Path;

use mlua::{Lua, LuaSerdeExt, Value};

use crate::error::{NetProbeError, NetProbeResult};
use crate::models::HostResult;

const DEFAULT_LUA_RULES: &str = include_str!("../../lua/default_rules.lua");

pub fn run(host: &HostResult, script_path: Option<&Path>) -> NetProbeResult<Vec<String>> {
    let script = if let Some(path) = script_path {
        fs::read_to_string(path)?
    } else {
        DEFAULT_LUA_RULES.to_string()
    };

    let lua = Lua::new();
    lua.load(&script).set_name("netprobe_rules").exec()?;
    let analyze = lua
        .globals()
        .get::<mlua::Function>("analyze")
        .map_err(|_| NetProbeError::Parse("lua script must define analyze(host)".to_string()))?;

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
            return Err(NetProbeError::Parse(
                "analyze(host) must return string, table, or nil".to_string(),
            ));
        }
    }

    Ok(findings)
}
