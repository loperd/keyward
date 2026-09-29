//! The register of accounts. There can be several: a work vault and a personal
//! one live side by side, one switches between them, and logging out of one
//! must not touch the other.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// A stable identifier: the login and the server address together. One and
    /// the same login on two servers is two different accounts.
    pub id: String,
    pub base_url: String,
    pub email: String,
    pub identity_url: Option<String>,
}

impl Account {
    pub fn new(base_url: &str, email: &str, identity_url: Option<&str>) -> Self {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let email = email.trim().to_string();
        Self {
            id: format!("{email}@{base_url}"),
            base_url,
            email,
            identity_url: identity_url.map(str::trim).filter(|s| !s.is_empty()).map(|s| {
                s.trim_end_matches('/').to_string()
            }),
        }
    }

    /// A short name for the server, for the interface: `vault.example.net`.
    pub fn host(&self) -> &str {
        self.base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub active: Option<String>,
}

impl Registry {
    pub fn load() -> Self {
        let path = crate::paths::accounts_file();
        let Ok(text) = std::fs::read_to_string(&path) else { return Self::default() };
        serde_json::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = crate::paths::accounts_file();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn active(&self) -> Option<&Account> {
        self.active.as_deref().and_then(|id| self.get(id))
    }

    /// Adds an account or updates one that exists, and makes it active.
    pub fn upsert(&mut self, account: Account) {
        match self.accounts.iter_mut().find(|a| a.id == account.id) {
            Some(existing) => *existing = account.clone(),
            None => self.accounts.push(account.clone()),
        }
        self.active = Some(account.id);
    }

    /// Removes an account. Any that is left becomes the active one: the
    /// interface must not end up in a state of "there are accounts and none is
    /// chosen".
    pub fn remove(&mut self, id: &str) {
        self.accounts.retain(|a| a.id != id);
        if self.active.as_deref() == Some(id) {
            self.active = self.accounts.first().map(|a| a.id.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(email: &str, url: &str) -> Account {
        Account::new(url, email, None)
    }

    #[test]
    fn same_login_on_two_servers_are_two_accounts() {
        let a = acc("me@example.com", "https://one.net");
        let b = acc("me@example.com", "https://two.net");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn trailing_slash_does_not_create_a_duplicate() {
        assert_eq!(acc("me@x.com", "https://one.net/").id, acc("me@x.com", "https://one.net").id);
    }

    #[test]
    fn upsert_replaces_and_activates() {
        let mut r = Registry::default();
        r.upsert(acc("a@x.com", "https://one.net"));
        r.upsert(acc("b@x.com", "https://one.net"));
        assert_eq!(r.accounts.len(), 2);
        assert_eq!(r.active().unwrap().email, "b@x.com");

        r.upsert(Account::new("https://one.net", "a@x.com", Some("https://id.one.net")));
        assert_eq!(r.accounts.len(), 2, "adding again must not breed duplicates");
        assert_eq!(r.active().unwrap().identity_url.as_deref(), Some("https://id.one.net"));
    }

    #[test]
    fn removing_active_falls_back_to_another() {
        let mut r = Registry::default();
        r.upsert(acc("a@x.com", "https://one.net"));
        r.upsert(acc("b@x.com", "https://one.net"));
        let active = r.active().unwrap().id.clone();
        r.remove(&active);
        assert!(r.active().is_some(), "after the active one is removed another has to stay chosen");
        assert_eq!(r.accounts.len(), 1);
    }

    #[test]
    fn removing_the_last_one_leaves_nothing_active() {
        let mut r = Registry::default();
        r.upsert(acc("a@x.com", "https://one.net"));
        let id = r.active().unwrap().id.clone();
        r.remove(&id);
        assert!(r.active().is_none());
        assert!(r.accounts.is_empty());
    }

    #[test]
    fn host_is_shown_without_scheme() {
        assert_eq!(acc("a@x.com", "https://vault.example.net").host(), "vault.example.net");
    }
}
