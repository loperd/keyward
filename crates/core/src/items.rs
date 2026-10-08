//! The vault's model for the interface: items of every kind, folders and
//! counts.
//!
//! There is not one secret here. Passwords, private keys and codes do not leave
//! the daemon — the interface needs a name, a kind and a row's caption in order
//! to show a list and let it be searched.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Card,
    Identity,
    SecureNote,
    SshKey,
}

impl ItemKind {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::SecureNote => "note",
            Self::SshKey => "ssh_key",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub kind: ItemKind,
    /// The second line in the list: a login, a card's last digits, a key's
    /// fingerprint.
    pub subtitle: Option<String>,
    /// The card network inferred locally from the PAN's IIN (or read from the
    /// vault's explicit brand). It is only a label — neither a PAN nor its
    /// visible prefix ever crosses the daemon/UI boundary.
    #[serde(default)]
    pub card_brand: Option<String>,
    pub folder_id: Option<String>,
    pub folder_name: Option<String>,
    pub org_id: Option<String>,
    /// The addresses out of a login item: they have to be searchable too.
    #[serde(default)]
    pub uris: Vec<String>,
    /// The item's own `kw-*` fields: what they mean belongs to the plugin
    /// that reads them, and the list shows them because a person put them
    /// there.
    #[serde(default)]
    pub tags: std::collections::BTreeMap<String, String>,
    /// The item has a one-time code, and then it is copied straight from the
    /// list without opening the card.
    #[serde(default)]
    pub has_totp: bool,
    /// How many passkeys the item has: an icon in the list.
    #[serde(default)]
    pub passkeys: u32,
    #[serde(default)]
    pub favorite: bool,
    /// The item is in the trash.
    #[serde(default)]
    pub deleted: bool,
    /// The organisation's name and not only its identifier.
    #[serde(default)]
    pub org_name: Option<String>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    /// The item asks for the master password again.
    pub reprompt: bool,
    /// When the item was last changed on the server (ISO 8601): the ledger's
    /// "updated" column.
    #[serde(default)]
    pub revised: Option<String>,
    /// When a login's password was last changed (ISO 8601): an old one is a
    /// warning.
    #[serde(default)]
    pub password_revised: Option<String>,
    /// A card's expiry as `YYYY-MM`: expired or close to it is a signal.
    #[serde(default)]
    pub expires: Option<String>,
    /// How many other items carry the very same password. Counted inside the
    /// daemon from salted hashes; no password and no hash leaves it.
    #[serde(default)]
    pub reused: u32,
    /// Which items share a password with this one: a number within one
    /// catalogue, the same for all of them; `None` when the password is its
    /// own. A number, not a hash.
    #[serde(default)]
    pub reuse_group: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub count: usize,
}

/// One's role in an organisation, as the server has it.
///
/// The server speaks numbers — 0 owner, 1 admin, 2 user, 3 manager, 4 custom
/// — and only this type knows them: everything above it, the window included,
/// speaks the role itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    Owner,
    Admin,
    User,
    Manager,
    Custom,
    /// A number the server sent that is in no documentation: shown as such,
    /// and trusted with nothing.
    Unknown,
}

impl OrgRole {
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Owner,
            1 => Self::Admin,
            2 => Self::User,
            3 => Self::Manager,
            4 => Self::Custom,
            _ => Self::Unknown,
        }
    }

    /// The server's number; none for a role it did not name.
    pub fn code(self) -> Option<i32> {
        match self {
            Self::Owner => Some(0),
            Self::Admin => Some(1),
            Self::User => Some(2),
            Self::Manager => Some(3),
            Self::Custom => Some(4),
            Self::Unknown => None,
        }
    }
}

/// What the server lets a custom role do, from the `permissions` it sends
/// with the organisation. Only what keyward acts on is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPermissions {
    pub manage_users: bool,
    pub create_new_collections: bool,
    pub edit_any_collection: bool,
    pub delete_any_collection: bool,
}

/// What one may do in an organisation, worked out the way a Bitwarden client
/// works it out from what the server sent: the role and the permissions.
/// The window asks this rather than comparing roles itself, and the daemon
/// checks it again before a request goes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgRights {
    pub role: OrgRole,
    pub permissions: OrgPermissions,
}

impl OrgRights {
    pub fn is_owner(&self) -> bool {
        self.role == OrgRole::Owner
    }

    pub fn is_admin(&self) -> bool {
        matches!(self.role, OrgRole::Owner | OrgRole::Admin)
    }

    /// A custom role's permission, or nothing for any other role: the fixed
    /// roles carry their rights in the role itself.
    fn custom(&self, granted: bool) -> bool {
        self.role == OrgRole::Custom && granted
    }

    /// The organisation's own settings — its name, its billing — and deleting
    /// it: the server keeps both for owners.
    pub fn can_edit_org(&self) -> bool {
        self.is_owner()
    }

    /// Inviting, confirming and removing members, changing their roles.
    pub fn can_manage_users(&self) -> bool {
        self.is_admin() || self.custom(self.permissions.manage_users)
    }

    pub fn can_create_collections(&self) -> bool {
        self.is_admin() || self.custom(self.permissions.create_new_collections)
    }

    pub fn can_edit_collections(&self) -> bool {
        self.is_admin() || self.custom(self.permissions.edit_any_collection)
    }

    pub fn can_delete_collections(&self) -> bool {
        self.is_admin() || self.custom(self.permissions.delete_any_collection)
    }

    /// Everything the window needs to know, worked out once.
    pub fn view(&self) -> OrgAbilities {
        OrgAbilities {
            edit_org: self.can_edit_org(),
            manage_users: self.can_manage_users(),
            create_collections: self.can_create_collections(),
            edit_collections: self.can_edit_collections(),
            delete_collections: self.can_delete_collections(),
            assignable_roles: self.assignable(),
        }
    }

    /// May one change or remove this member? Nobody but an owner touches an
    /// owner, and nobody edits themselves here.
    pub fn can_edit(&self, target: OrgRole, is_you: bool) -> bool {
        self.can_manage_users() && !is_you && (target != OrgRole::Owner || self.is_owner())
    }

    /// The roles one may hand out; only an owner makes an owner.
    pub fn assignable(&self) -> Vec<OrgRole> {
        if !self.can_manage_users() {
            return Vec::new();
        }
        let mut roles = vec![OrgRole::User, OrgRole::Manager, OrgRole::Admin];
        if self.is_owner() {
            roles.push(OrgRole::Owner);
        }
        roles
    }
}

/// What one may do in an organisation, as the window gets it: flags to show
/// or hide a control by, never a role to compare.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgAbilities {
    pub edit_org: bool,
    pub manage_users: bool,
    pub create_collections: bool,
    pub edit_collections: bool,
    pub delete_collections: bool,
    /// The roles one may give a member here.
    pub assignable_roles: Vec<OrgRole>,
}

/// An organisation, with its own name and one's role in it. An identifier is
/// not enough: people know organisations by name and decide by role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub role: OrgRole,
    pub can: OrgAbilities,
    pub count: usize,
}

/// Where a member stands: invited, accepted, confirmed, revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Revoked,
    Invited,
    Accepted,
    Confirmed,
    /// Vaultwarden sends things that are not in the documentation either —
    /// 128, for instance. Lying about such a thing is not allowed.
    Unknown,
}

impl MemberStatus {
    pub fn from_code(code: i32) -> Self {
        match code {
            -1 => Self::Revoked,
            0 => Self::Invited,
            1 => Self::Accepted,
            2 => Self::Confirmed,
            _ => Self::Unknown,
        }
    }
}

/// A member's level of access to one collection: the server's three flags
/// (`readOnly`, `hidePasswords`, `manage`) read as the one level they mean,
/// the way Bitwarden's own clients read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionPermission {
    /// Edit the items and manage the collection itself.
    Manage,
    /// Edit the items, passwords included.
    Edit,
    /// Edit the items without seeing their passwords.
    EditHidden,
    /// See the items, passwords included.
    Read,
    /// See the items without their passwords.
    ReadHidden,
}

impl CollectionPermission {
    /// `manage` outranks the rest: the server sends it with the other two
    /// flags clear, but a manager is a manager whatever they say.
    pub fn from_flags(read_only: bool, hide_passwords: bool, manage: bool) -> Self {
        match (manage, read_only, hide_passwords) {
            (true, _, _) => Self::Manage,
            (false, true, true) => Self::ReadHidden,
            (false, true, false) => Self::Read,
            (false, false, true) => Self::EditHidden,
            (false, false, false) => Self::Edit,
        }
    }

    /// The flags a level is sent to the server as: `(read_only,
    /// hide_passwords, manage)`.
    pub fn flags(self) -> (bool, bool, bool) {
        match self {
            Self::Manage => (false, false, true),
            Self::Edit => (false, false, false),
            Self::EditHidden => (false, true, false),
            Self::Read => (true, false, false),
            Self::ReadHidden => (true, true, false),
        }
    }
}

/// One collection a member was given by name, and at what level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionAccess {
    pub id: String,
    pub permission: CollectionPermission,
}

/// A member of an organisation, already in the shape they are shown in.
///
/// The server's numbers are a detail of the protocol, and one layer should be
/// the one that knows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub id: String,
    /// The user's identifier: their public key is fetched by it when a member
    /// is confirmed.
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub email: String,
    pub role: OrgRole,
    pub status: MemberStatus,
    pub two_factor: bool,
    /// Access to every collection of the organisation at once.
    pub access_all: bool,
    /// The collections given by name, each with its level. Empty with
    /// `access_all`.
    #[serde(default)]
    pub access: Vec<CollectionAccess>,
    /// This is the owner of the account we are looking from.
    pub is_you: bool,
    /// Whether the one looking may change this member's role or remove them.
    pub can_edit: bool,
    /// Whether the one looking may confirm them: they have accepted, and
    /// confirming is managing members.
    pub can_confirm: bool,
}

#[cfg(test)]
mod rights_tests {
    use super::*;

    #[test]
    fn the_servers_flags_read_as_one_level_and_back() {
        use CollectionPermission as P;
        assert_eq!(P::from_flags(false, false, false), P::Edit);
        assert_eq!(P::from_flags(false, true, false), P::EditHidden);
        assert_eq!(P::from_flags(true, false, false), P::Read);
        assert_eq!(P::from_flags(true, true, false), P::ReadHidden);
        // A manager is a manager, whatever the other flags say.
        for (ro, hide) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(P::from_flags(ro, hide, true), P::Manage);
        }
        for p in [P::Manage, P::Edit, P::EditHidden, P::Read, P::ReadHidden] {
            let (ro, hide, manage) = p.flags();
            assert_eq!(P::from_flags(ro, hide, manage), p, "{p:?} must survive the round trip");
        }
        assert_eq!(serde_json::to_string(&P::ReadHidden).unwrap(), r#""read_hidden""#);
        assert_eq!(serde_json::to_string(&P::EditHidden).unwrap(), r#""edit_hidden""#);
    }

    #[test]
    fn a_member_from_an_older_daemon_has_no_access_list() {
        let raw = r#"{"id":"m","user_id":null,"name":null,"email":"a@b.c","role":"user",
            "status":"confirmed","two_factor":false,"access_all":false,"collections":2,
            "is_you":false,"can_edit":true,"can_confirm":false}"#;
        // Its count of collections is passed over: `access` says which.
        let m: OrgMember = serde_json::from_str(raw).expect("parses");
        assert!(m.access.is_empty());
    }

    fn rights(role: OrgRole, manage_users: bool) -> OrgRights {
        OrgRights {
            role,
            permissions: OrgPermissions {
                manage_users,
                ..Default::default()
            },
        }
    }

    #[test]
    fn nobody_but_an_owner_touches_an_owner() {
        let admin = rights(OrgRole::Admin, false);
        assert!(!admin.can_edit(OrgRole::Owner, false));
        assert!(admin.can_edit(OrgRole::User, false));
        assert!(!admin.assignable().contains(&OrgRole::Owner));
        let owner = rights(OrgRole::Owner, false);
        assert!(owner.can_edit(OrgRole::Owner, false));
        assert!(owner.assignable().contains(&OrgRole::Owner));
        // Nobody edits themselves here.
        assert!(!owner.can_edit(OrgRole::User, true));
    }

    #[test]
    fn members_are_managed_by_role_or_by_permission() {
        assert!(!rights(OrgRole::User, false).can_manage_users());
        assert!(!rights(OrgRole::Manager, false).can_manage_users());
        assert!(!rights(OrgRole::Custom, false).can_manage_users());
        assert!(rights(OrgRole::Custom, true).can_manage_users());
        assert!(rights(OrgRole::Unknown, true).assignable().is_empty());
    }

    #[test]
    fn only_an_owner_edits_or_deletes_the_organisation() {
        assert!(rights(OrgRole::Owner, false).can_edit_org());
        assert!(!rights(OrgRole::Admin, false).can_edit_org());
        assert!(!rights(OrgRole::Custom, true).can_edit_org());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionView {
    pub id: String,
    pub name: String,
    pub org_id: Option<String>,
    pub read_only: bool,
    pub count: usize,
}

/// Everything needed to draw the vault: the items, the folders and the counts
/// by kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub items: Vec<VaultItem>,
    pub folders: Vec<Folder>,
    /// How many items of each kind: `login`, `card`, `identity`, `note`,
    /// `ssh_key`.
    pub counts: Vec<(String, usize)>,
    /// How many items lie outside any folder.
    pub unfiled: usize,
    /// The organisations, with their names and roles.
    #[serde(default)]
    pub orgs: Vec<Org>,
    #[serde(default)]
    pub collections: Vec<CollectionView>,
    /// How many items are in the trash and among the favourites.
    #[serde(default)]
    pub trash: usize,
    #[serde(default)]
    pub favorites: usize,
}

impl Catalog {
    /// Builds the folders and the counts out of items that are already parsed,
    /// so that there is one source of truth: the list itself.
    /// Builds the counts out of items that are already parsed, so that there
    /// is one source of truth: the list itself.
    ///
    /// The trash does not count towards the kinds and the folders: a deleted
    /// item must not swell "Logins", or the number in the rail does not match
    /// the list.
    pub fn build(
        items: Vec<VaultItem>,
        folder_names: &[(String, String)],
        orgs: &[Org],
        collections: &[CollectionView],
    ) -> Self {
        use std::collections::BTreeMap;

        let mut per_folder: BTreeMap<&str, usize> = BTreeMap::new();
        let mut per_kind: BTreeMap<&str, usize> = BTreeMap::new();
        let mut per_org: BTreeMap<&str, usize> = BTreeMap::new();
        let mut per_collection: BTreeMap<&str, usize> = BTreeMap::new();
        let (mut unfiled, mut trash, mut favorites) = (0, 0, 0);

        for item in &items {
            if item.deleted {
                trash += 1;
                continue;
            }
            if item.favorite {
                favorites += 1;
            }
            *per_kind.entry(item.kind.slug()).or_default() += 1;
            match item.folder_id.as_deref() {
                Some(id) => *per_folder.entry(id).or_default() += 1,
                None => unfiled += 1,
            }
            if let Some(org) = item.org_id.as_deref() {
                *per_org.entry(org).or_default() += 1;
            }
            for c in &item.collection_ids {
                *per_collection.entry(c.as_str()).or_default() += 1;
            }
        }

        let mut folders: Vec<Folder> = folder_names
            .iter()
            .map(|(id, name)| Folder {
                id: id.clone(),
                name: name.clone(),
                count: per_folder.get(id.as_str()).copied().unwrap_or(0),
            })
            .collect();
        folders.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let mut orgs: Vec<Org> = orgs
            .iter()
            .map(|o| Org {
                count: per_org.get(o.id.as_str()).copied().unwrap_or(0),
                ..o.clone()
            })
            .collect();
        orgs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let mut collections: Vec<CollectionView> = collections
            .iter()
            .map(|c| CollectionView {
                count: per_collection.get(c.id.as_str()).copied().unwrap_or(0),
                ..c.clone()
            })
            .collect();
        collections.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let counts = ["login", "card", "identity", "note", "ssh_key"]
            .iter()
            .map(|k| ((*k).to_string(), per_kind.get(k).copied().unwrap_or(0)))
            .collect();

        Self {
            items,
            folders,
            counts,
            unfiled,
            orgs,
            collections,
            trash,
            favorites,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str, kind: ItemKind, folder: Option<&str>) -> VaultItem {
        VaultItem {
            id: name.to_string(),
            name: name.to_string(),
            kind,
            subtitle: None,
            card_brand: None,
            folder_id: folder.map(str::to_string),
            folder_name: None,
            org_id: None,
            uris: Vec::new(),
            tags: Default::default(),
            has_totp: false,
            passkeys: 0,
            favorite: false,
            deleted: false,
            org_name: None,
            collection_ids: Vec::new(),
            reprompt: false,
            revised: None,
            password_revised: None,
            expires: None,
            reused: 0,
            reuse_group: None,
        }
    }

    #[test]
    fn counts_every_kind_even_when_empty() {
        let c = Catalog::build(vec![item("a", ItemKind::Login, None)], &[], &[], &[]);
        let map: std::collections::HashMap<_, _> = c.counts.into_iter().collect();
        assert_eq!(map["login"], 1);
        // A zero has to arrive too: otherwise a row disappears from the side
        // panel.
        assert_eq!(map["card"], 0);
        assert_eq!(map["ssh_key"], 0);
    }

    #[test]
    fn folder_counts_and_unfiled_add_up() {
        let items = vec![
            item("a", ItemKind::Login, Some("f1")),
            item("b", ItemKind::Card, Some("f1")),
            item("c", ItemKind::Login, None),
        ];
        let c = Catalog::build(items, &[("f1".into(), "Work".into())], &[], &[]);
        assert_eq!(c.folders[0].count, 2);
        assert_eq!(c.unfiled, 1);
    }

    #[test]
    fn folders_are_sorted_case_insensitively() {
        let c = Catalog::build(
            Vec::new(),
            &[("2".into(), "apple".into()), ("1".into(), "Orange".into())],
            &[],
            &[],
        );
        assert_eq!(
            c.folders
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["apple", "Orange"]
        );
    }

    #[test]
    fn organizations_carry_names_and_counts() {
        let mut a = item("a", ItemKind::Login, None);
        a.org_id = Some("org".into());
        let mut b = item("b", ItemKind::Login, None);
        b.org_id = Some("org".into());
        let orgs = [Org {
            id: "org".into(),
            name: "Acme".into(),
            role: OrgRole::User,
            can: OrgAbilities::default(),
            count: 0,
        }];
        let c = Catalog::build(vec![a, b], &[], &orgs, &[]);
        assert_eq!(c.orgs.len(), 1);
        assert_eq!(c.orgs[0].name, "Acme");
        assert_eq!(c.orgs[0].count, 2);
    }

    #[test]
    fn trash_is_counted_apart_and_does_not_inflate_types() {
        let mut gone = item("a", ItemKind::Login, Some("f1"));
        gone.deleted = true;
        let mut fav = item("b", ItemKind::Login, None);
        fav.favorite = true;
        let c = Catalog::build(vec![gone, fav], &[("f1".into(), "Work".into())], &[], &[]);
        assert_eq!(c.trash, 1);
        assert_eq!(c.favorites, 1);
        let map: std::collections::HashMap<_, _> = c.counts.into_iter().collect();
        // A deleted item must reach neither a kind nor a folder.
        assert_eq!(map["login"], 1);
        assert_eq!(c.folders[0].count, 0);
    }
}
