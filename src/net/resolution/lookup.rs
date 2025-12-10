use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use pnet::util::MacAddr;

#[derive(Debug)]
struct Elem {
    mac: MacAddr,
    ts: Instant,
}

#[derive(Debug)]
pub struct LookupTable {
    table: DashMap<IpAddr, Elem>,
    ttl: Option<Duration>,
}

impl LookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            ttl: None,
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            table: DashMap::new(),
            ttl: Some(ttl),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<MacAddr> {
        let elem = self.table.get(&ip)?;

        if let Some(ttl) = self.ttl.as_ref()
            && elem.ts.elapsed() > *ttl
        {
            self.table.remove(&ip);
            return None;
        }
        Some(elem.mac)
    }

    pub fn insert(&self, ip: IpAddr, mac: MacAddr) -> Option<MacAddr> {
        self.table
            .insert(
                ip,
                Elem {
                    mac,
                    ts: Instant::now(),
                },
            )
            .map(|elem| elem.mac)
    }
}
