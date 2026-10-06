//! The servers the vault's keys reach, by name: what a plugin that works on
//! servers can offer to go to.
//!
//! A route with a wildcard names no server and is left out; a server behind a
//! jump host or a proxy command is listed but marked, since nothing here goes
//! through one yet.

use keyward_plugin::VaultEntry;
use serde::Serialize;

use crate::mapping::MappingTable;
use crate::remote::Login;
use crate::sshconfig;
use crate::table;

/// What a server is missing before anything may connect to it. Nothing is
/// guessed in its place: not a login from a banner, not port 22.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    Login,
    Port,
}

/// One server one key reaches.
#[derive(Debug, Clone, Serialize)]
pub struct Machine {
    pub entry_id: String,
    pub entry_name: String,
    /// The name as the route has it.
    pub host: String,
    /// Where it connects: `HostName` for an alias, otherwise the host.
    pub address: String,
    /// Zero when nothing names one; see `missing`.
    pub port: u16,
    /// `None` when neither the route, the item nor the config says.
    pub user: Option<String>,
    #[serde(skip)]
    pub pin: Option<String>,
    /// The jump host or proxy command the config sends it through.
    pub proxy: Option<String>,
    /// What is not set up. A server with anything here is not connected to.
    pub missing: Vec<Missing>,
}

impl Machine {
    /// The login for it, with the item's public key.
    pub fn login(&self, entry: &VaultEntry) -> anyhow::Result<Login> {
        if self.missing.contains(&Missing::Port) {
            anyhow::bail!(keyward_core::fault!("err.sshPortRequired", "host" => self.host.as_str()));
        }
        if let Some(through) = &self.proxy {
            anyhow::bail!(keyward_core::fault!("err.sshJumpUnsupported", "host" => self.host.as_str(), "jump" => through.as_str()));
        }
        let user = self
            .user
            .clone()
            .ok_or_else(|| keyward_core::fault!("err.sshLoginRequired", "host" => self.host.as_str()))?;
        Ok(Login {
            entry_id: self.entry_id.clone(),
            entry_name: self.entry_name.clone(),
            host: self.host.clone(),
            address: self.address.clone(),
            port: self.port,
            user,
            key: table::public_key(entry)?,
            pin: self.pin.clone(),
        })
    }
}

/// The servers, and what could not be read — an item with a broken `kw-port`
/// is said so rather than skipped in silence.
#[derive(Debug, Default)]
pub struct Machines {
    pub list: Vec<Machine>,
    pub broken: Vec<anyhow::Error>,
}

/// Every server named outright by a route of a key with a public half. One
/// row per key and server: a second name that leads to the same address and
/// port adds nothing.
pub fn machines(entries: &[VaultEntry], routes: &MappingTable, ssh: &sshconfig::Config) -> Machines {
    let mut out = Machines::default();
    for e in entries.iter().filter(|e| e.public_key.is_some()) {
        let own_port = match table::port_field(e) {
            Ok(p) => p,
            Err(err) => {
                out.broken.push(err);
                continue;
            }
        };
        let own_user = table::user_field(e);
        for m in routes.mappings.iter().filter(|m| m.entry_id == e.id && !crate::glob::has_wildcard(&m.host)) {
            let conf = ssh.lookup(&m.host);
            let address = conf.hostname.clone().unwrap_or_else(|| m.host.clone());
            // The route's, the item's or the config's — never assumed.
            let port = m.port.or(own_port).or(conf.port);
            let user = m.user.clone().or_else(|| own_user.clone()).or_else(|| conf.user.clone());
            let mut missing = Vec::new();
            if user.is_none() {
                missing.push(Missing::Login);
            }
            if port.is_none() {
                missing.push(Missing::Port);
            }
            let port = port.unwrap_or(0);
            if out.list.iter().any(|x| x.entry_id == e.id && x.address.eq_ignore_ascii_case(&address) && x.port == port) {
                continue;
            }
            out.list.push(Machine {
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                host: m.host.clone(),
                address,
                port,
                user,
                pin: m.hostkey.clone().or_else(|| e.field(table::HOSTKEY).map(str::to_string)),
                proxy: conf.proxy().map(str::to_string),
                missing,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, hosts: &str, fields: &[(&str, &str)]) -> VaultEntry {
        let mut e = VaultEntry::default();
        e.id = id.into();
        e.name = id.to_uppercase();
        e.public_key = Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ".into());
        e.set_field(table::HOST, hosts);
        for (k, v) in fields {
            e.set_field(k, *v);
        }
        e
    }

    #[test]
    fn named_routes_become_servers_and_wildcards_do_not() {
        let entries = vec![key("a", "alex@db.example.com:2222, *.lab, box, bare", &[(table::USER, "root")])];
        let (routes, _) = table::build_table(&entries);
        let ssh = sshconfig::Config::parse("Host box\n  HostName 10.0.0.7\n  Port 2200\n");
        let got = machines(&entries, &routes, &ssh);
        assert!(got.broken.is_empty());
        let rows: Vec<(&str, &str, u16, Option<&str>)> =
            got.list.iter().map(|m| (m.host.as_str(), m.address.as_str(), m.port, m.user.as_deref())).collect();
        assert_eq!(
            rows,
            vec![("db.example.com", "db.example.com", 2222, Some("alex")), ("box", "10.0.0.7", 2200, Some("root")), ("bare", "bare", 0, Some("root"))]
        );
        // No port anywhere: not 22 by guess, but not set up.
        assert_eq!(got.list[2].missing, vec![Missing::Port]);
        assert!(got.list[2].login(&entries[0]).err().unwrap().to_string().starts_with("err.sshPortRequired"));
        assert!(got.list[0].missing.is_empty());
    }

    #[test]
    fn a_broken_port_is_said_so_and_a_proxy_is_refused_at_login() {
        let entries = vec![key("a", "db", &[(table::PORT, "twenty")]), key("b", "far", &[(table::USER, "u"), (table::PORT, "22")])];
        let (routes, _) = table::build_table(&entries);
        let ssh = sshconfig::Config::parse("Host far\n  ProxyJump bastion\n");
        let got = machines(&entries, &routes, &ssh);
        assert_eq!(got.broken.len(), 1);
        assert_eq!(got.list.len(), 1);
        assert!(got.list[0].login(&entries[1]).is_err());
    }
}
