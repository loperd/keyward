//! A thin layer over the Accessibility API for the code cells: find the row
//! of one-character boxes a field belongs to and move the focus from box to
//! box.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, CFTypeRef, TCFType as _};
use core_foundation::boolean::CFBoolean;
use core_foundation::string::{CFString, CFStringRef};

#[repr(C)]
struct AXUIElement(std::ffi::c_void);
type AXUIElementRef = *const AXUIElement;
#[repr(C)]
#[derive(Default)]
struct Pair {
    a: f64,
    b: f64,
}
const AX_VALUE_CG_POINT: u32 = 1;
const AX_VALUE_CG_SIZE: u32 = 2;
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> AXUIElementRef;
    fn AXUIElementCopyAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: *mut CFTypeRef) -> i32;
    fn AXUIElementSetAttributeValue(element: AXUIElementRef, attribute: CFStringRef, value: CFTypeRef) -> i32;
    fn AXValueGetValue(value: CFTypeRef, kind: u32, out: *mut std::ffi::c_void) -> bool;
}

pub fn app(pid: i32) -> Option<CFType> {
    if pid <= 0 {
        return None;
    }
    let el = unsafe { AXUIElementCreateApplication(pid) };
    (!el.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(el as CFTypeRef) })
}

pub fn attr(el: &CFType, name: &str) -> Option<CFType> {
    let key = CFString::new(name);
    let mut out: CFTypeRef = std::ptr::null();
    let err = unsafe { AXUIElementCopyAttributeValue(el.as_CFTypeRef() as AXUIElementRef, key.as_concrete_TypeRef(), &mut out) };
    (err == 0 && !out.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(out) })
}

pub fn string(el: &CFType, name: &str) -> String {
    attr(el, name).and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string()).unwrap_or_default()
}

fn pair(el: &CFType, name: &str, kind: u32) -> Option<(f64, f64)> {
    let v = attr(el, name)?;
    let mut p = Pair::default();
    let ok = unsafe { AXValueGetValue(v.as_CFTypeRef(), kind, &mut p as *mut Pair as *mut std::ffi::c_void) };
    ok.then_some((p.a, p.b))
}

fn children(el: &CFType) -> Vec<CFType> {
    let Some(list) = attr(el, "AXChildren").and_then(|v| v.downcast::<CFArray>()) else { return Vec::new() };
    list.iter().map(|c| unsafe { CFType::wrap_under_get_rule(*c as CFTypeRef) }).collect()
}

pub fn focus(el: &CFType) -> bool {
    let key = CFString::new("AXFocused");
    let yes = CFBoolean::true_value();
    unsafe { AXUIElementSetAttributeValue(el.as_CFTypeRef() as AXUIElementRef, key.as_concrete_TypeRef(), yes.as_CFTypeRef()) == 0 }
}

/// Is this something a character can be typed into?
pub fn typable(role: &str, subrole: &str) -> bool {
    subrole == "AXSecureTextField"
        || matches!(role, "AXTextField" | "AXTextArea" | "AXComboBox" | "AXSearchField" | "AXIncrementor" | "AXSpinButton")
}

/// The fields under `el`, in the order of the tree, no deeper than `depth`.
/// With `lists`, drop-down lists count as fields too: a card's month and
/// year are often a `select`.
fn fields_under(el: &CFType, depth: usize, lists: bool, out: &mut Vec<CFType>) {
    for c in children(el) {
        let role = string(&c, "AXRole");
        if typable(&role, &string(&c, "AXSubrole")) || (lists && role == "AXPopUpButton") {
            out.push(c);
        } else if depth > 0 {
            fields_under(&c, depth - 1, lists, out);
        }
    }
}

/// What a field is captioned with, for telling the fields of a form apart:
/// the caption, the description, the placeholder and the page's own `id`.
pub fn captions(el: &CFType) -> String {
    ["AXTitle", "AXDescription", "AXPlaceholderValue", "AXDOMIdentifier"]
        .into_iter()
        .map(|a| string(el, a))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A field of a form, with what it takes to tell it apart.
pub struct FormField {
    pub el: CFType,
    pub role: String,
    pub subrole: String,
    pub captions: String,
}

/// The form around the focused field, grown outwards one container at a
/// time until `enough` is satisfied by what has been gathered, or the page
/// runs out. Nearest first: a whole checkout page is thousands of nodes, and
/// each of them is a round trip to another process.
///
/// The depth reaches into frames: a card's fields often live each in an
/// iframe of its own (Stripe), and Accessibility shows them all in one tree.
/// The fields come back top to bottom, left to right.
pub fn form_around(pid: i32, enough: impl Fn(&[FormField]) -> bool) -> Vec<FormField> {
    let Some(mut cur) = app(pid).and_then(|a| attr(&a, "AXFocusedUIElement")) else { return Vec::new() };
    let mut best = Vec::new();
    for _ in 0..12 {
        let Some(parent) = attr(&cur, "AXParent") else { break };
        if string(&parent, "AXRole") == "AXWindow" {
            break;
        }
        let mut els = Vec::new();
        fields_under(&parent, 10, true, &mut els);
        let mut fields: Vec<(f64, f64, FormField)> = els
            .into_iter()
            .map(|el| {
                let (x, y) = pair(&el, "AXPosition", AX_VALUE_CG_POINT).unwrap_or_default();
                let f = FormField { role: string(&el, "AXRole"), subrole: string(&el, "AXSubrole"), captions: captions(&el), el };
                (y, x, f)
            })
            .collect();
        fields.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
        best = fields.into_iter().map(|f| f.2).collect();
        if enough(&best) {
            break;
        }
        cur = parent;
    }
    best
}

/// A row of one-character boxes is how sites ask for a one-time code:
/// six inputs, each holding one digit, the focus hopping on by itself.
/// Typed as one string, the whole code lands in the first box and the
/// page reads garbage — it has to be typed box by box.
///
/// The row is recognised by its shape rather than its captions, which
/// such boxes rarely have: the nearest container that holds more than
/// one field holds 4 to 8 of them, of one role, narrow, of one size and
/// on one line. The boxes come back left to right.
pub fn code_cells(focused: &CFType) -> Vec<CFType> {
    let role = string(focused, "AXRole");
    let mut cur = focused.clone();
    for _ in 0..4 {
        let Some(parent) = attr(&cur, "AXParent") else { break };
        let mut fields = Vec::new();
        fields_under(&parent, 3, false, &mut fields);
        if fields.len() < 2 {
            cur = parent;
            continue;
        }
        if !(4..=8).contains(&fields.len()) || !fields.contains(focused) {
            return Vec::new();
        }
        let mut boxes = Vec::with_capacity(fields.len());
        for f in fields {
            if string(&f, "AXRole") != role {
                return Vec::new();
            }
            let (Some((x, y)), Some((w, h))) = (pair(&f, "AXPosition", AX_VALUE_CG_POINT), pair(&f, "AXSize", AX_VALUE_CG_SIZE)) else {
                return Vec::new();
            };
            boxes.push((x, y, w, h, f));
        }
        let (w0, h0) = (boxes[0].2, boxes[0].3);
        let y0 = boxes[0].1;
        let alike = boxes.iter().all(|b| b.2 <= 90.0 && (b.2 - w0).abs() <= 4.0 && (b.3 - h0).abs() <= 4.0 && (b.1 - y0).abs() <= h0 / 2.0);
        if !alike {
            return Vec::new();
        }
        boxes.sort_by(|a, b| a.0.total_cmp(&b.0));
        return boxes.into_iter().map(|b| b.4).collect();
    }
    Vec::new()
}

/// The row of code boxes that holds the application's focus right now.
pub fn focused_cells(pid: i32) -> Vec<CFType> {
    app(pid).and_then(|a| attr(&a, "AXFocusedUIElement")).map(|f| code_cells(&f)).unwrap_or_default()
}

/// The fields of the nearest container around the focus that holds more
/// than one field, top to bottom, left to right — and whether the focused
/// field is among them. Deliberately narrow: a login form is small, and
/// reaching further out finds some other page's password box.
pub fn nearest_group(pid: i32) -> Vec<(FormField, bool)> {
    let Some(focused) = app(pid).and_then(|a| attr(&a, "AXFocusedUIElement")) else { return Vec::new() };
    let mut cur = focused.clone();
    for _ in 0..8 {
        let Some(parent) = attr(&cur, "AXParent") else { break };
        if string(&parent, "AXRole") == "AXWindow" {
            break;
        }
        let mut els = Vec::new();
        fields_under(&parent, 6, false, &mut els);
        if els.len() >= 2 {
            let mut fields: Vec<(f64, f64, FormField, bool)> = els
                .into_iter()
                .map(|el| {
                    let (x, y) = pair(&el, "AXPosition", AX_VALUE_CG_POINT).unwrap_or_default();
                    let on = el == focused;
                    (y, x, FormField { role: string(&el, "AXRole"), subrole: string(&el, "AXSubrole"), captions: captions(&el), el }, on)
                })
                .collect();
            fields.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
            return fields.into_iter().map(|f| (f.2, f.3)).collect();
        }
        cur = parent;
    }
    Vec::new()
}
