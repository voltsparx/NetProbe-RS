use std::collections::BTreeSet;

use crate::models::HostResult;

mod device_safety;
mod framework;
mod services;
mod tbns;

pub fn build_host_notes(host: &HostResult) -> Vec<String> {
    let mut notes = BTreeSet::new();
    framework::collect(host, &mut notes);
    services::collect(host, &mut notes);
    device_safety::collect(host, &mut notes);
    tbns::collect(host, &mut notes);
    notes.into_iter().collect()
}
