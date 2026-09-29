/// What the plugin answers — the Rust types of `keyward_plugin_vaultwarden`.
/// The window draws these as they come: what a user's state allows and which
/// roles may be given are worked out by the plugin, not here.
import type { MemberStatus, OrgRole } from "@keyward/types";

export type UserState = "enabled" | "invited" | "disabled";

export type UserAction = "resend_invite" | "disable" | "enable" | "deauth" | "remove_two_factor" | "delete";

export type Membership = { org_id: string; org_name: string; role: OrgRole; status: MemberStatus };

export type AdminUser = {
  id: string;
  name: string | null;
  email: string;
  state: UserState;
  two_factor: boolean;
  email_verified: boolean;
  created_at: string | null;
  last_active: string | null;
  memberships: Membership[];
  actions: ActionView[];
};

/// An action with how carefully it is offered — decided by the plugin.
export type ActionView = { action: UserAction; danger: boolean; confirm: boolean };

export type UsersOut = { users: AdminUser[]; assignable_roles: OrgRole[] };

export type OrgMember = { user_id: string; email: string; name: string | null; role: OrgRole; status: MemberStatus };

export type AdminOrg = { id: string; name: string; members: OrgMember[]; owners: number };

/// A server setting as the panel has it — `settings::Setting`.
export type SettingKind = "text" | "number" | "password" | "checkbox";
export type Setting = {
  name: string;
  label: string;
  description: string;
  kind: SettingKind;
  value: string | number | boolean | null;
  default: string | null;
  editable: boolean;
  overridden: boolean;
  /// A picker instead of free text, with what to pick from — the plugin's.
  choice: Choice | null;
};

/// Some of the server's users; the words the server reads as everyone and
/// nobody, and how a list is joined, come with it.
export type Choice = { kind: "users"; options: string[]; all: string; none: string; separator: string };
export type SettingsGroup = { id: string; title: string; settings: Setting[] };
