// A verb's preview, described: what will happen, step by step, what changes
// and what stays — before anything happens. Nothing runs until ↵; the effect
// names what the backend is asked to do then.
import type { Kdf } from "../settings/types";
import type { Key, Text } from "../i18n";
import type { Lead, MarkSpec } from "../doc/spec";
import type { Level, OrgRole, Permission, SecretRef } from "../model/types";
import type { Invite } from "../writes";

export type DeltaSide = MarkSpec | { faint: Text };
export type Delta = { lead: Lead; name: Text; mono?: boolean; from: DeltaSide; to: DeltaSide };
export type Line = { level: Level; title: Text; sub?: Text };

/// What ↵ asks of the backend. `none` is a verb the backend cannot do yet:
/// the preview still shows, and the window says that nothing was changed.
export type Effect = { copy: SecretRef } | { lock: true } | { trash: string[] } | { restore: string[] } | { sync: true } | { org: OrgWrite } | { folder: FolderWrite } | { plugin: PluginCall } | { account: AccountWrite } | { none: true };

/// A change to how this account opens on this computer.
export enum AccountOp {
  RememberBiometric = "rememberBiometric",
  ForgetBiometric = "forgetBiometric",
  SetPin = "setPin",
  ClearPin = "clearPin",
  Export = "export",
  ChangePassword = "changePassword",
  ChangeKdf = "changeKdf",
  Deauthorize = "deauthorize",
  Purge = "purge",
  DeleteAccount = "deleteAccount",
}

/// What an export is written as.
export enum ExportFormat {
  Json = "json",
  Csv = "csv",
}
/// `secrets`: what the person typed into the preview's secret fields, by the
/// field's id — `null` in the preview, put in by the window at ↵ from fields
/// that are emptied as they are read (`withSecrets`). Never kept anywhere.
export type AccountWrite =
  | { op: Exclude<AccountOp, AccountOp.Export | AccountOp.ChangeKdf>; secrets: Readonly<Record<string, string>> | null }
  | { op: AccountOp.Export; format: ExportFormat; secrets: Readonly<Record<string, string>> | null }
  | { op: AccountOp.ChangeKdf; kdf: Kdf; secrets: Readonly<Record<string, string>> | null };

/// What a secret field of a preview is for: a field the line never carries
/// (a master password, a PIN), typed into the sheet and read once at ↵.
export enum SecretAskKind {
  Password = "password",
  NewPassword = "newPassword",
  Pin = "pin",
}
/// `same`: the id of the field it must repeat; `differs`: the id of one it
/// must not repeat (a new password is not the current one); `min`: its
/// shortest length, with `short` the words for a shorter one.
export type SecretAsk = { id: string; label: Text; kind: SecretAskKind; same?: string; differs?: string; min?: number; short?: Key };

/// One of a plugin's actions, asked of the backend as the plugin declared it:
/// the core does not read into `op` or `payload`.
export type PluginCall = { plugin: string; op: string; payload: unknown };

/// A change to the vault's folders: one call of `Writes` each.
export enum FolderOp {
  Create = "create",
  Rename = "rename",
  Delete = "delete",
}
export type FolderWrite = { op: FolderOp.Create; name: string } | { op: FolderOp.Rename; id: string; name: string } | { op: FolderOp.Delete; id: string };

/// A change to an organisation, named: one call of `Writes` each.
export enum OrgOp {
  Invite = "invite",
  SetMember = "setMember",
  ConfirmMember = "confirmMember",
  RemoveMember = "removeMember",
  CreateCollection = "createCollection",
  RenameCollection = "renameCollection",
  DeleteCollection = "deleteCollection",
}
export type OrgWrite =
  | { op: OrgOp.Invite; orgId: string; invite: Invite }
  | { op: OrgOp.SetMember; orgId: string; memberId: string; change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> } }
  /// `fingerprint` is the member's five words as the window showed them:
  /// `null` in the preview, filled in by the window once they are on screen
  /// (`withShownFingerprint`). The backend seals only to a key that still
  /// makes them.
  | { op: OrgOp.ConfirmMember; orgId: string; memberId: string; fingerprint: string[] | null }
  | { op: OrgOp.RemoveMember; orgId: string; memberId: string }
  | { op: OrgOp.CreateCollection; orgId: string; name: string }
  | { op: OrgOp.RenameCollection; orgId: string; id: string; name: string }
  | { op: OrgOp.DeleteCollection; orgId: string; id: string };

/// One choice of a preview's control: the words, the line's argument it
/// leads to, whether it stands now, and why it cannot be taken, if it cannot.
export type Choice = { label: Text; arg: string; on: boolean; off?: Text };
/// What a preview lets a person set before ↵. Every control writes the
/// line's argument, so the line, the URL and the sheet never disagree.
export type Input =
  | { id: string; label: Text; lead?: Lead; text: string; placeholder?: Text; mono?: boolean; with: (value: string) => string }
  | { id: string; label: Text; lead?: Lead; choices: Choice[]; toggle?: Toggle };
/// A switch beside a row of choices, as an icon with its words in a tooltip
/// (passwords hidden, beside a collection's level).
export type Toggle = { icon: string; label: Text; on: boolean; arg: string; off?: Text };
export type FormGroup = { title?: Text; inputs: Input[] };

export enum PreviewKind {
  Ready = "ready",
  Pick = "pick",
  Unknown = "unknown",
}
export type Preview =
  | {
      kind: PreviewKind.Ready;
      target: string | null;
      title: Text;
      lede: Text;
      steps: { title: Text; sub: Text }[];
      changes?: { rows: Delta[]; count?: number };
      now?: Line[];
      stays?: Line[];
      go: Text;
      /// The quiet promise beside the buttons ("will ask for your
      /// fingerprint").
      note?: Text;
      effect: Effect;
      /// The controls, above the steps.
      form?: FormGroup[];
      /// Why ↵ cannot run yet (or ever, here): said beside the disabled
      /// button.
      blocked?: Text;
      /// It takes something away: the button says so in its colour.
      danger?: boolean;
      /// Secret fields typed into the sheet, read at ↵ and never kept.
      secrets?: SecretAsk[];
      /// A member whose fingerprint phrase the window fetches and shows
      /// before ↵ may run; `compare` tells the person what to do with it.
      fingerprint?: { orgId: string; memberId: string; compare: Text };
    }
  /// The verb is known, the object is not one it works on.
  | { kind: PreviewKind.Pick; verb: string; name: Text; obj: string | null; example: string | null; exampleName: Text | null }
  | { kind: PreviewKind.Unknown; verb: string; known: Text[] };
