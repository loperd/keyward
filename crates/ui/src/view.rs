//! What a plugin's screen is made of, said as data.
//!
//! The plugin declares; keyward carries it out. A plugin never ships a line
//! of its own TypeScript, CSS or HTML: it builds these nodes and the window
//! draws them with its own kit, by the design rules that hold for every
//! screen. Whatever can live in the window lives there — filtering, sorting,
//! tabs, a form's fields, the text in an editor; the plugin is asked only for
//! what needs its context: the data, and what an action does.
//!
//! Every word a person reads is a dictionary key of the plugin's (with
//! arguments, the way errors travel): `Text::key("kube.servers")`. A value
//! that is data — a host name, a pod — is `Text::raw`.

use serde::Serialize;
use serde_json::Value;

/// Something a person reads: a key of the plugin's dictionary, or a value as
/// it is.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Text {
    Key { key: String, #[serde(skip_serializing_if = "Value::is_null")] args: Value },
    Raw { raw: String },
}

impl Text {
    pub fn key(key: &str) -> Self {
        Self::Key { key: key.to_string(), args: Value::Null }
    }
    pub fn key_with(key: &str, args: Value) -> Self {
        Self::Key { key: key.to_string(), args }
    }
    pub fn raw(value: impl Into<String>) -> Self {
        Self::Raw { raw: value.into() }
    }
}

/// The colour a state is said in.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    #[default]
    Plain,
    Ok,
    Warn,
    Bad,
    Accent,
}

/// What pressing something does: an operation of the plugin's, carried out
/// by keyward — asked first, when the operation is one to be sure of.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Action {
    pub op: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub payload: Value,
    /// Asked before it goes: the person types this word — an object's name
    /// before it is deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
    /// Asked lightly: the first press arms the button, a second within a
    /// few seconds carries it out — for what is easily undone or redone, a
    /// pod a controller brings back.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub twice: bool,
}

impl Action {
    pub fn op(op: &str) -> Self {
        Self { op: op.to_string(), payload: Value::Null, confirm: None, twice: false }
    }
    pub fn with(op: &str, payload: Value) -> Self {
        Self { op: op.to_string(), payload, confirm: None, twice: false }
    }
    pub fn confirmed_by(mut self, word: impl Into<String>) -> Self {
        self.confirm = Some(word.into());
        self
    }
    pub fn pressed_twice(mut self) -> Self {
        self.twice = true;
        self
    }
}

/// A button. Icon-only when it has no label: the words go to the tooltip.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Button {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub title: Text,
    #[serde(skip_serializing_if = "is_plain")]
    pub tone: Tone,
    /// The one main action of the screen.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub primary: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub busy: bool,
    pub action: Action,
}

fn is_plain(t: &Tone) -> bool {
    *t == Tone::Plain
}

impl Button {
    /// An icon button; `title` is its word.
    pub fn icon(icon: &str, title: Text, action: Action) -> Self {
        Self { label: None, icon: Some(icon.to_string()), title, tone: Tone::Plain, primary: false, disabled: false, busy: false, action }
    }
    /// A button with words.
    pub fn labelled(label: Text, action: Action) -> Self {
        Self { title: label.clone(), label: Some(label), icon: None, tone: Tone::Plain, primary: false, disabled: false, busy: false, action }
    }
    pub fn with_icon(mut self, icon: &str) -> Self {
        self.icon = Some(icon.to_string());
        self
    }
    pub fn primary(mut self) -> Self {
        self.primary = true;
        self
    }
    pub fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }
    pub fn disabled(mut self, yes: bool) -> Self {
        self.disabled = yes;
        self
    }
    pub fn busy(mut self, yes: bool) -> Self {
        self.busy = yes;
        self
    }
}

/// A chip: a state or a kind said in a word and a colour.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Chip {
    pub label: Text,
    #[serde(skip_serializing_if = "is_plain")]
    pub tone: Tone,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Text>,
    /// A dot before the word: a state rather than a kind.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dot: bool,
}

impl Chip {
    pub fn new(label: Text) -> Self {
        Self { label, tone: Tone::Plain, icon: None, title: None, dot: false }
    }
    pub fn state(label: Text, tone: Tone) -> Self {
        Self { label, tone, icon: None, title: None, dot: true }
    }
    pub fn icon(mut self, icon: &str) -> Self {
        self.icon = Some(icon.to_string());
        self
    }
    pub fn title(mut self, title: Text) -> Self {
        self.title = Some(title);
        self
    }
}

/// A row of a list: an object with its state and what can be done with it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ListRow {
    pub key: String,
    pub icon: String,
    #[serde(skip_serializing_if = "is_plain")]
    pub tone: Tone,
    /// Being worked on right now: the dot pulses.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub busy: bool,
    pub title: Text,
    /// The title is a value — a host, a name — set in the monospaced face.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mono: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<Text>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chips: Vec<Chip>,
    /// A line said in the row's tone: why it failed, what it waits for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
    /// A value to compare by eye: a fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// When it was last looked at, seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Button>,
    /// A press on the row itself: the whole row (or card) opens it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<Action>,
}

impl ListRow {
    pub fn new(key: impl Into<String>, icon: &str, title: Text) -> Self {
        Self { key: key.into(), icon: icon.to_string(), tone: Tone::Plain, busy: false, title, mono: false, subtitle: None, chips: Vec::new(), note: None, code: None, at: None, actions: Vec::new(), open: None }
    }
}

/// A column of a table. The window sorts and filters; the plugin gives each
/// row its values.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Column {
    pub id: String,
    pub title: Text,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sortable: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mono: bool,
}

/// A facet a table is filtered by: the select and the `id:value` word in the
/// search.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Facet {
    pub id: String,
    pub title: Text,
    pub icon: String,
}

/// What a cell shows.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Cell {
    Text { text: Text },
    Chip { chip: Chip },
    /// Seconds since the epoch, shown as "5 minutes ago".
    Ago { at: u64 },
    Empty,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TableRow {
    pub key: String,
    pub cells: serde_json::Map<String, Value>,
    /// Each facet's value, for the selects and the search.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub facets: serde_json::Map<String, Value>,
    /// What each sortable column sorts by, when it is not the cell's text.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub sort: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<Action>,
    /// What can be done to the row without opening it: icons at its end.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Button>,
}

impl TableRow {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into(), cells: Default::default(), facets: Default::default(), sort: Default::default(), open: None, actions: Vec::new() }
    }
    pub fn cell(mut self, column: &str, cell: Cell) -> Self {
        self.cells.insert(column.to_string(), serde_json::to_value(cell).unwrap_or(Value::Null));
        self
    }
    pub fn facet(mut self, facet: &str, value: Option<&str>) -> Self {
        if let Some(v) = value {
            self.facets.insert(facet.to_string(), Value::String(v.to_string()));
        }
        self
    }
    pub fn sort(mut self, column: &str, value: impl Into<Value>) -> Self {
        self.sort.insert(column.to_string(), value.into());
        self
    }
    pub fn open(mut self, action: Action) -> Self {
        self.open = Some(action);
        self
    }
    pub fn action(mut self, button: Button) -> Self {
        self.actions.push(button);
        self
    }
}

/// A field of a form. What is typed stays in the window until the form is
/// sent.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Field {
    pub id: String,
    pub label: Text,
    pub kind: FieldKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    /// A secret: never echoed back into the form, sealed on its way.
    Secret,
    /// Many lines: a kubeconfig, a manifest.
    Area,
    Number { min: i64, max: i64 },
    Select { options: Vec<(String, Text)> },
    /// On or off: the form sends `"true"` or `"false"`.
    Toggle,
}

/// One node of a screen.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Node {
    /// A heading over what follows, with its icon, tone and count; folded
    /// ones open on a press.
    Section {
        title: Text,
        icon: String,
        #[serde(skip_serializing_if = "is_plain")]
        tone: Tone,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<usize>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        folded: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        hint: Option<Text>,
        body: Vec<Node>,
    },
    List { rows: Vec<ListRow> },
    /// The same rows as cards in a grid: a catalog of connections, each with
    /// its state, opened by a press on it.
    Cards { cards: Vec<ListRow> },
    Table {
        /// The window keeps the table's filters and sort under this name.
        id: String,
        columns: Vec<Column>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        facets: Vec<Facet>,
        rows: Vec<TableRow>,
        #[serde(skip_serializing_if = "Option::is_none")]
        empty: Option<Text>,
    },
    /// Tabs the window switches itself; a tab's body comes from the plugin
    /// when it is shown (`load`), or is given whole.
    Tabs {
        id: String,
        /// Icons alone, the words in the tooltips.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        icons_only: bool,
        /// The tab shown first, over the one the person had on last.
        #[serde(skip_serializing_if = "Option::is_none")]
        on: Option<String>,
        tabs: Vec<Tab>,
    },
    /// A value that is chosen and sent: a namespace for a whole screen.
    Select {
        id: String,
        icon: String,
        title: Text,
        value: String,
        options: Vec<(String, Text)>,
        action: Action,
    },
    Form { fields: Vec<Field>, submit: Button },
    /// Text as it is: a log, a manifest.
    Pre { text: String },
    /// Text a person changes and applies — checked first: the plugin's
    /// `check` answers what would change (`before`, `after`), and only then
    /// is `apply` offered.
    Editor { text: String, check: Action, apply: Action },
    /// A terminal: `open` gives a stream id; the window writes, reads,
    /// resizes and closes through the ops named here.
    Terminal { open: Action, read: String, write: String, resize: String, close: String },
    /// What cannot be taken back: the person types `confirm` first.
    Danger { title: Text, hint: Text, button: Button },
    Chips { chips: Vec<Chip> },
    Actions { buttons: Vec<Button> },
    Alert {
        text: Text,
        #[serde(skip_serializing_if = "is_plain")]
        tone: Tone,
    },
    Empty {
        icon: String,
        title: Text,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<Text>,
    },
    /// Waiting: a spinner and a word.
    Busy { text: Text },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tab {
    pub id: String,
    pub title: Text,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<Action>,
    /// Ask `load` again this often while the tab is on screen: a list that
    /// changes under the person's eyes. The window keeps the filters, the sort
    /// and the scroll across the answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<Node>,
}

/// A breadcrumb back.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Crumb {
    pub label: Text,
    pub action: Action,
}

/// A whole screen, or a drawer's contents.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Page {
    pub title: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crumb: Option<Crumb>,
    /// In place of the title: the switcher between the section's connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switcher: Option<Switcher>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chips: Vec<Chip>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Button>,
    pub body: Vec<Node>,
    /// Ask again in this many milliseconds: a scan under way, a cluster
    /// opening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_ms: Option<u64>,
}

/// One of the things a section works with — a cluster, a server — as the
/// switcher lists it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SwitchItem {
    pub key: String,
    pub label: Text,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<Text>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot: Option<Tone>,
    /// The route it opens.
    pub route: String,
}

/// The switcher in a screen's head: which connection the screen is of, the
/// others a press away, adding one, and the catalog of them all. A section has
/// no column of its own: what it works with lives here and in the catalog.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Switcher {
    /// The key of the item the screen is of.
    pub current: String,
    pub items: Vec<SwitchItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<Button>,
    /// The catalog's route and its name: "All clusters".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<SwitchItem>,
}

/// What an action leaves behind: the window does the rest.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Reply {
    /// Go to this route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go: Option<String>,
    /// Open a drawer with this; `close_drawer` closes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drawer: Option<Page>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub close_drawer: bool,
    /// A dialogue over the screen: a form to fill, an editor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialog: Option<Page>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub close_dialog: bool,
    /// Said in a toast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toast: Option<Text>,
    /// Ask for the screen again.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub refresh: bool,
    /// Data for the node that asked: an editor's check, a stream's chunk.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

impl Reply {
    pub fn refresh() -> Self {
        Self { refresh: true, ..Self::default() }
    }
    pub fn go(route: impl Into<String>) -> Self {
        Self { go: Some(route.into()), ..Self::default() }
    }
    pub fn drawer(page: Page) -> Self {
        Self { drawer: Some(page), ..Self::default() }
    }
    pub fn dialog(page: Page) -> Self {
        Self { dialog: Some(page), ..Self::default() }
    }
    pub fn data(data: impl Serialize) -> anyhow::Result<Self> {
        Ok(Self { data: serde_json::to_value(data)?, ..Self::default() })
    }
}
