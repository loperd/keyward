//! Resolving a host to exactly one vault item.
//!
//! The main property the whole thing exists for: for any host, **one** item has
//! to be found. So `resolve` returns an `Option<Resolution>` rather than a list:
//! there is no trying key after key, and not by agreement but by type.

use serde::{Deserialize, Serialize};

use crate::glob;

/// A vault item that declared which hosts it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    /// The item's identifier in the vault.
    pub entry_id: String,
    /// The item's name: shown in the GUI and used as the last deterministic
    /// tie-breaker.
    pub entry_name: String,
    /// The original pattern out of the `kw-host` field, as a person wrote it.
    pub pattern: String,
    /// The login, if the pattern was of the form `user@host`.
    pub user: Option<String>,
    /// The host pattern without the login and the port.
    pub host: String,
    /// The port, if the pattern was of the form `host:port`.
    pub port: Option<u16>,
    /// The Vault SSH CA role out of `kw-cert`; when it is set, a fresh
    /// certificate is offered instead of a static key.
    pub cert_role: Option<String>,
    /// `kw-confirm: yes` demands a confirmation for every signature.
    pub confirm: bool,
    /// The server's expected host key out of `kw-hostkey`; `None` means trust
    /// on first use.
    pub hostkey: Option<String>,
}

impl Mapping {
    /// Parses one pattern of the form `[user@]host[:port]`.
    pub fn parse_pattern(entry_id: &str, entry_name: &str, pattern: &str) -> anyhow::Result<Self> {
        let raw = pattern.trim();
        if raw.is_empty() {
            return Err(keyward_core::fault!("err.emptyPattern", "item" => entry_name));
        }

        let (user, rest) = match raw.split_once('@') {
            Some((u, r)) if !u.is_empty() && !r.is_empty() => (Some(u.to_string()), r),
            Some(_) => return Err(keyward_core::fault!("err.patternEmptyPart", "pattern" => raw, "item" => entry_name)),
            None => (None, raw),
        };

        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| keyward_core::fault!("err.patternBadPort", "pattern" => raw, "port" => p))?;
                (h.to_string(), Some(port))
            }
            _ => (rest.to_string(), None),
        };

        Ok(Self {
            entry_id: entry_id.to_string(),
            entry_name: entry_name.to_string(),
            pattern: raw.to_string(),
            user,
            host,
            port,
            cert_role: None,
            confirm: false,
            hostkey: None,
        })
    }

    /// Does the mapping suit the destination asked for?
    pub fn matches(&self, host: &str, user: Option<&str>, port: Option<u16>) -> bool {
        if !glob::matches(&self.host, host) {
            return false;
        }
        // A login and a port in a pattern are extra conditions. If they are set
        // and the request did not report them, or reported others, the mapping
        // does not suit.
        if let Some(want) = &self.user {
            match user {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        if let Some(want) = self.port {
            match port {
                Some(got) if got == want => {}
                _ => return false,
            }
        }
        true
    }

    /// A measure of specificity. Compared lexicographically, and more means
    /// more specific: an exact host name beats a glob, then comes the length of
    /// the literal part, then the narrowing by login and port.
    fn specificity(&self) -> (u8, usize, u8, u8) {
        (
            u8::from(!glob::has_wildcard(&self.host)),
            glob::literal_len(&self.host),
            u8::from(self.user.is_some()),
            u8::from(self.port.is_some()),
        )
    }
}

/// The result of resolving: the winning mapping and a sign that the win was
/// ambiguous (several mappings of equal specificity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub mapping: Mapping,
    /// The names of the items that lost the tie-break. Not empty means a person
    /// wrote ambiguous patterns, and the GUI is obliged to show it.
    pub ambiguous_with: Vec<String>,
}

/// The table of every mapping, gathered out of the vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingTable {
    pub mappings: Vec<Mapping>,
}

impl MappingTable {
    pub fn new(mappings: Vec<Mapping>) -> Self {
        Self { mappings }
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Finds the one mapping for a destination. The winner is decided by
    /// specificity, and a tie by the item's name and pattern, so that the
    /// result does not depend on the order the vault was read in.
    pub fn resolve(&self, host: &str, user: Option<&str>, port: Option<u16>) -> Option<Resolution> {
        let mut candidates: Vec<&Mapping> = self
            .mappings
            .iter()
            .filter(|m| m.matches(host, user, port))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        candidates.sort_by(|a, b| {
            b.specificity()
                .cmp(&a.specificity())
                .then_with(|| a.entry_name.cmp(&b.entry_name))
                .then_with(|| a.pattern.cmp(&b.pattern))
        });

        let winner = candidates[0];
        let ambiguous_with = candidates
            .iter()
            .skip(1)
            .filter(|m| m.specificity() == winner.specificity())
            .map(|m| m.entry_name.clone())
            .collect();

        Some(Resolution {
            mapping: winner.clone(),
            ambiguous_with,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, pattern: &str) -> Mapping {
        Mapping::parse_pattern(name, name, pattern).expect("the pattern must parse")
    }

    #[test]
    fn parses_plain_host() {
        let p = m("gitlab", "git.example.com");
        assert_eq!(p.host, "git.example.com");
        assert!(p.user.is_none() && p.port.is_none());
    }

    #[test]
    fn parses_user_and_port() {
        let p = m("node", "admin@node1.example.net:2222");
        assert_eq!(p.user.as_deref(), Some("admin"));
        assert_eq!(p.host, "node1.example.net");
        assert_eq!(p.port, Some(2222));
    }

    #[test]
    fn rejects_garbage_port() {
        assert!(Mapping::parse_pattern("x", "x", "host:notaport").is_err());
        assert!(Mapping::parse_pattern("x", "x", "").is_err());
        assert!(Mapping::parse_pattern("x", "x", "@host").is_err());
    }

    #[test]
    fn exact_host_beats_glob() {
        let t = MappingTable::new(vec![m("wide", "*.example.net"), m("exact", "node1.example.net")]);
        let r = t.resolve("node1.example.net", None, None).unwrap();
        assert_eq!(r.mapping.entry_name, "exact");
        assert!(r.ambiguous_with.is_empty());
    }

    #[test]
    fn longer_literal_tail_beats_shorter() {
        let t = MappingTable::new(vec![m("any", "*"), m("dom", "*.example.net")]);
        let r = t.resolve("node1.example.net", None, None).unwrap();
        assert_eq!(r.mapping.entry_name, "dom");
    }

    #[test]
    fn user_qualified_wins_when_user_matches() {
        let t = MappingTable::new(vec![m("bare", "node1.example.net"), m("asadmin", "admin@node1.example.net")]);
        let r = t.resolve("node1.example.net", Some("admin"), None).unwrap();
        assert_eq!(r.mapping.entry_name, "asadmin");
    }

    #[test]
    fn user_qualified_is_skipped_for_other_user() {
        let t = MappingTable::new(vec![m("bare", "node1.example.net"), m("asadmin", "admin@node1.example.net")]);
        let r = t.resolve("node1.example.net", Some("deploy"), None).unwrap();
        assert_eq!(r.mapping.entry_name, "bare");
    }

    #[test]
    fn no_match_returns_none() {
        let t = MappingTable::new(vec![m("dom", "*.example.net")]);
        assert!(t.resolve("git.example.com", None, None).is_none());
    }

    #[test]
    fn tie_is_reported_and_broken_deterministically() {
        // Two items of equal specificity: the winner has to be stable and the
        // fact of the tie has to be visible.
        let t = MappingTable::new(vec![m("zeta", "*.example.net"), m("alpha", "*.example.net")]);
        let r = t.resolve("node1.example.net", None, None).unwrap();
        assert_eq!(r.mapping.entry_name, "alpha");
        assert_eq!(r.ambiguous_with, vec!["zeta".to_string()]);

        // Reading the vault in the opposite order does not change the outcome.
        let t2 = MappingTable::new(vec![m("alpha", "*.example.net"), m("zeta", "*.example.net")]);
        assert_eq!(t2.resolve("node1.example.net", None, None).unwrap().mapping.entry_name, "alpha");
    }

    #[test]
    fn port_qualified_requires_port() {
        let t = MappingTable::new(vec![m("p2222", "node1.example.net:2222")]);
        assert!(t.resolve("node1.example.net", None, Some(22)).is_none());
        assert!(t.resolve("node1.example.net", None, Some(2222)).is_some());
    }

    // -- Edge cases, added by the red team --------------------------------

    #[test]
    fn ipv6_pattern_is_silently_misparsed_as_host_plus_port() {
        // DEFECT: rsplit_once(':') cuts the last group of an IPv6 address off
        // and takes it for a port number. The parse goes through with no error
        // and no warning, and after that the mapping matches nothing and the
        // key silently disappears.
        let p = m("v6", "2001:db8::1");
        assert_eq!(p.host, "2001:db8:");
        assert_eq!(p.port, Some(1));
        let t = MappingTable::new(vec![p]);
        assert!(t.resolve("2001:db8::1", None, None).is_none(),
                "an IPv6 mapping ought to work, and does not");
    }

    #[test]
    fn bracketed_ipv6_does_not_match_what_ssh_passes() {
        // DEFECT: ssh gives %h without brackets, so an item of `[::1]:22` is
        // dead.
        let t = MappingTable::new(vec![m("v6", "[::1]:22")]);
        assert_eq!(t.mappings[0].host, "[::1]");
        assert_eq!(t.mappings[0].port, Some(22));
        assert!(t.resolve("::1", None, Some(22)).is_none());
    }

    #[test]
    fn catch_all_offers_the_key_to_every_host() {
        // One item with `kw-host: *` hands its key to any server, other
        // people's included. There is neither an error nor a warning for it —
        // only an entry in ambiguous_with, which here is empty.
        let t = MappingTable::new(vec![m("catch-all", "*")]);
        for host in ["github.com", "someone.elses.server", "attacker.example", ""] {
            let r = t.resolve(host, None, None);
            assert!(r.is_some(), "the star has to catch {host:?}");
            assert!(r.unwrap().ambiguous_with.is_empty(), "and warn nobody");
        }
    }

    #[test]
    fn empty_host_resolves_against_wildcard() {
        // DEFECT: an empty %h is not a host name and must not be resolved.
        let t = MappingTable::new(vec![m("any", "*")]);
        assert!(t.resolve("", None, None).is_some());
    }

    #[test]
    fn username_comparison_is_case_insensitive_but_unix_logins_are_not() {
        // DEFECT: eq_ignore_ascii_case. On a server `Admin` and `admin` are
        // different accounts, and the key is offered to both.
        let t = MappingTable::new(vec![m("adm", "admin@node1.example.net")]);
        assert!(t.resolve("node1.example.net", Some("Admin"), None).is_some());
        assert!(t.resolve("node1.example.net", Some("ADMIN"), None).is_some());
    }

    #[test]
    fn wildcards_in_the_user_part_are_not_supported() {
        // A defect of expectations: a `*` in a login is compared literally
        // rather than as a glob. A person who wrote `*@host` means "any login"
        // and gets "a login consisting of a star".
        let t = MappingTable::new(vec![m("u", "*@node1.example.net")]);
        assert!(t.resolve("node1.example.net", Some("deploy"), None).is_none());
        assert!(t.resolve("node1.example.net", Some("*"), None).is_some());
    }

    #[test]
    fn host_matching_ignores_case_of_the_query() {
        let t = MappingTable::new(vec![m("g", "git.example.com")]);
        assert!(t.resolve("GIT.Example.CoM", None, None).is_some());
    }

    #[test]
    fn port_zero_pattern_can_never_be_matched() {
        // The CLI turns port 0 into None, so `host:0` is a dead item.
        let t = MappingTable::new(vec![m("p0", "node1.example.net:0")]);
        assert_eq!(t.mappings[0].port, Some(0));
        assert!(t.resolve("node1.example.net", None, None).is_none());
        assert!(t.resolve("node1.example.net", None, Some(0)).is_some());
    }

    #[test]
    fn port_out_of_range_is_rejected() {
        assert!(Mapping::parse_pattern("x", "x", "host:65536").is_err());
        assert!(Mapping::parse_pattern("x", "x", "host:-1").is_err());
        assert!(Mapping::parse_pattern("x", "x", "host: 22").is_err());
    }

    #[test]
    fn several_at_signs_take_the_first_one() {
        // `a@b@host` gives the login `a` and the host `b@host`. Not an error,
        // and not what a person meant either.
        let p = m("x", "a@b@node1.example.net");
        assert_eq!(p.user.as_deref(), Some("a"));
        assert_eq!(p.host, "b@node1.example.net");
    }

    #[test]
    fn tie_across_different_patterns_is_reported() {
        // Two different patterns of equal specificity, both of which suit. The
        // winner is deterministic, but the loser has to be shown.
        let t = MappingTable::new(vec![m("zeta", "*.example.net"), m("alpha", "node?.exampl?.net")]);
        let r = t.resolve("node1.example.net", None, None).unwrap();
        assert_eq!(r.mapping.entry_name, "alpha");
        assert_eq!(r.ambiguous_with.len(), 0,
                   "the specificity differs and there is no tie, but the narrower pattern won");
    }

    #[test]
    fn longer_literal_tail_outweighs_user_qualification() {
        // The order of fields in specificity: the length of the host's literal
        // first, the login after. So a longer glob beats an exact login.
        let t = MappingTable::new(vec![
            m("byuser", "deploy@*.example.net"),
            m("byhost", "*.internal.example.net"),
        ]);
        let r = t.resolve("a.internal.example.net", Some("deploy"), None).unwrap();
        assert_eq!(r.mapping.entry_name, "byhost");
    }

    #[test]
    fn hosts_differing_only_in_unicode_are_distinct_mappings() {
        // Here they honestly differ. The trap is further down the stack:
        // paths::agent_socket folds them into one socket file — see the test in
        // paths.rs.
        let t = MappingTable::new(vec![m("de", "münchen.corp"), m("se", "mänchen.corp")]);
        assert_eq!(t.resolve("münchen.corp", None, None).unwrap().mapping.entry_name, "de");
        assert_eq!(t.resolve("mänchen.corp", None, None).unwrap().mapping.entry_name, "se");
    }
}
