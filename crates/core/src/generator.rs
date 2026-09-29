//! The password generator.
//!
//! It lives in the daemon rather than in the interface: the randomness comes
//! from the system through `getrandom` and not from the webview's
//! `Math.random`, and a secret keeps to one and the same path — the one the
//! vault's passwords travel.

use serde::{Deserialize, Serialize};

/// The generator's history: what was shown and what was carried off to the
/// clipboard. It holds live passwords: wiped when dropped, and never printed.
#[derive(Clone, Default, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct History {
    pub made: Vec<String>,
    pub taken: Vec<String>,
    /// The identifiers of recently opened items, for a search that has to show
    /// something before anybody starts typing.
    #[serde(default)]
    pub recent: Vec<String>,
}

impl std::fmt::Debug for History {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "History({} made, {} taken, {} recent)", self.made.len(), self.taken.len(), self.recent.len())
    }
}

impl History {
    /// What the window is shown of it: how many there are and how long each
    /// is. The values stay in the daemon; one is copied or shown by its place.
    pub fn view(&self) -> HistoryView {
        let lengths = |list: &[String]| list.iter().map(|v| v.chars().count()).collect();
        HistoryView { made: lengths(&self.made), taken: lengths(&self.taken) }
    }
}

/// The history as the window sees it: a length for each password, no value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryView {
    pub made: Vec<usize>,
    pub taken: Vec<usize>,
}

/// What exactly to generate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Throw the look-alike characters out: `0O1lI`. A password dictated aloud
    /// or copied off a screen suffers more from them than it gains in
    /// strength.
    pub avoid_ambiguous: bool,
    /// Neither begin nor end with a punctuation mark.
    ///
    /// A common and silly demand, but a real one: somebody else's forms either
    /// trim the outer characters or refuse to take them, and the password breaks
    /// after it has already been saved.
    #[serde(default)]
    pub symbols_inside_only: bool,
}

impl Default for Spec {
    fn default() -> Self {
        // Sixteen characters from four sets is about 104 bits, which is plenty
        // over and does not look like a mockery when typed by hand.
        Self {
            length: 16,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
            symbols_inside_only: false,
        }
    }
}

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// No quotes, no backslash and no space: those have to be escaped in configs
/// and in a shell, and the password breaks somewhere other than where it is
/// checked.
const SYMBOLS: &str = "!#$%&()*+,-.:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "0O1lI";

impl Spec {
    pub fn validate(&self) -> Result<(), String> {
        if !(self.upper || self.lower || self.digits || self.symbols) {
            return Err("err.generatorNoSet".into());
        }
        if self.length < 4 {
            return Err("err.generatorTooShort".into());
        }
        if self.length > 128 {
            return Err("err.generatorTooLong".into());
        }
        if self.symbols_inside_only && self.symbols && !(self.upper || self.lower || self.digits) {
            return Err("err.generatorEdgesImpossible".into());
        }
        if self.symbols_inside_only && self.symbols && self.length < 3 {
            return Err("err.generatorInsideNeedsThree".into());
        }
        Ok(())
    }

    /// The sets a password is assembled from.
    fn pools(&self) -> Vec<Vec<char>> {
        let keep = |src: &str| -> Vec<char> {
            src.chars().filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect()
        };
        [(self.upper, UPPER), (self.lower, LOWER), (self.digits, DIGITS), (self.symbols, SYMBOLS)]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, src)| keep(src))
            .filter(|pool| !pool.is_empty())
            .collect()
    }
}

/// A password's strength in bits, by the number of possibilities rather than
/// by "rules".
pub fn entropy_bits(spec: &Spec) -> f64 {
    let alphabet: usize = spec.pools().iter().map(Vec::len).sum();
    if alphabet <= 1 {
        return 0.0;
    }
    (alphabet as f64).log2() * spec.length as f64
}

/// Assembles a password.
///
/// At least one character is taken from every chosen set — otherwise "turn
/// digits on" guarantees nothing and the password may fail somebody else's
/// check. The rest is drawn from the common pot, and then the lot is
/// shuffled.
pub fn password(spec: &Spec) -> Result<String, String> {
    spec.validate()?;
    let pools = spec.pools();
    if pools.is_empty() {
        return Err("err.generatorNothingLeft".into());
    }
    if spec.length < pools.len() {
        return Err("err.generatorFewerThanSets".into());
    }

    let mut out: Vec<char> = pools.iter().map(|pool| pick(pool)).collect();
    let all: Vec<char> = pools.concat();
    while out.len() < spec.length {
        out.push(pick(&all));
    }
    shuffle(&mut out);
    if spec.symbols_inside_only && spec.symbols {
        keep_symbols_inside(&mut out)?;
    }
    Ok(out.into_iter().collect())
}

/// Takes punctuation off the edges by swapping it with characters from
/// inside.
///
/// Not "generate again until it comes out right": on short passwords with a
/// large share of punctuation that can take any number of attempts, while a
/// swap keeps both the composition and the evenness within.
fn keep_symbols_inside(items: &mut [char]) -> Result<(), String> {
    let last = items.len() - 1;
    for edge in [0, last] {
        if !SYMBOLS.contains(items[edge]) {
            continue;
        }
        let inner: Vec<usize> = (1..last).filter(|&i| !SYMBOLS.contains(items[i])).collect();
        if inner.is_empty() {
            // There is nothing to swap the edge with: the inside is all
            // punctuation. This used to pass silently, and the password came
            // out exactly as it had been asked not to — at short lengths, in
            // most cases. An honest refusal is better.
            return Err(
                "err.generatorCannotKeepInside"
                    .into(),
            );
        }
        // A random one is taken from the suitable insiders rather than the
        // first that comes to hand.
        let choice = inner[rand_below(inner.len() as u32) as usize];
        items.swap(edge, choice);
    }
    Ok(())
}

/// An even random number below `n`.
fn rand_below(n: u32) -> u32 {
    let limit = u32::MAX - (u32::MAX % n) - 1;
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("the system's source of randomness");
        let value = u32::from_le_bytes(buf);
        if value <= limit {
            return value % n;
        }
    }
}

/// An even choice of one character.
///
/// Values from the tail of the range are thrown away: a plain remainder makes
/// the first characters of a set slightly likelier than the rest, and over a
/// long run that shows.
fn pick(pool: &[char]) -> char {
    let n = pool.len() as u32;
    let limit = u32::MAX - (u32::MAX % n) - 1;
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("the system's source of randomness");
        let value = u32::from_le_bytes(buf);
        if value <= limit {
            return pool[(value % n) as usize];
        }
    }
}

/// A Fisher-Yates shuffle on the same source of randomness.
fn shuffle(items: &mut [char]) {
    for i in (1..items.len()).rev() {
        let n = (i + 1) as u32;
        let limit = u32::MAX - (u32::MAX % n) - 1;
        let j = loop {
            let mut buf = [0u8; 4];
            getrandom::fill(&mut buf).expect("the system's source of randomness");
            let value = u32::from_le_bytes(buf);
            if value <= limit {
                break (value % n) as usize;
            }
        };
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_history_never_shows_its_passwords() {
        let h = History { made: vec!["hunter2-made".into()], taken: vec!["hunter2-taken".into()], recent: vec![] };
        let shown = format!("{h:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        let view = serde_json::to_string(&h.view()).unwrap();
        assert!(!view.contains("hunter2"), "{view}");
        assert_eq!(h.view().made, vec![12]);
    }

    use super::*;

    #[test]
    fn the_length_is_kept() {
        for length in [4, 8, 16, 64, 128] {
            let spec = Spec { length, ..Spec::default() };
            assert_eq!(password(&spec).expect("a password").chars().count(), length);
        }
    }

    #[test]
    fn every_set_that_is_on_is_represented() {
        // A hundred runs: if the sets were filled at random, a missing digit
        // would surface almost certainly.
        let spec = Spec { length: 4, avoid_ambiguous: false, ..Spec::default() };
        for _ in 0..100 {
            let p = password(&spec).expect("a password");
            assert!(p.chars().any(|c| UPPER.contains(c)), "no capitals: {p}");
            assert!(p.chars().any(|c| LOWER.contains(c)), "no lower case: {p}");
            assert!(p.chars().any(|c| DIGITS.contains(c)), "no digits: {p}");
            assert!(p.chars().any(|c| SYMBOLS.contains(c)), "no punctuation: {p}");
        }
    }

    #[test]
    fn look_alike_characters_are_left_out() {
        let spec = Spec { length: 128, avoid_ambiguous: true, ..Spec::default() };
        let p = password(&spec).expect("a password");
        assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)), "look-alike characters were left in: {p}");
    }

    #[test]
    fn an_empty_set_is_refused() {
        let spec = Spec { upper: false, lower: false, digits: false, symbols: false, ..Spec::default() };
        assert!(password(&spec).is_err());
    }

    #[test]
    fn the_strength_is_counted_by_the_alphabet() {
        // Lower case only, look-alikes out: 25 characters, log2(25) is about
        // 4.64 per character.
        let spec = Spec {
            length: 10,
            upper: false,
            lower: true,
            digits: false,
            symbols: false,
            avoid_ambiguous: true,
            symbols_inside_only: false,
        };
        let bits = entropy_bits(&spec);
        assert!((bits - 46.4).abs() < 0.5, "an unexpected estimate: {bits}");
    }

    #[test]
    fn punctuation_stays_inside() {
        let spec = Spec { length: 8, symbols_inside_only: true, ..Spec::default() };
        for _ in 0..200 {
            let p = password(&spec).expect("a password");
            let first = p.chars().next().expect("the first character");
            let last = p.chars().last().expect("the last character");
            assert!(!SYMBOLS.contains(first), "punctuation at the start: {p}");
            assert!(!SYMBOLS.contains(last), "punctuation at the end: {p}");
            assert_eq!(p.chars().count(), 8);
        }
    }

    #[test]
    fn a_short_password_of_digits_and_punctuation_with_clean_edges_is_refused() {
        // A password with punctuation on an edge used to come out here
        // silently, in most runs, and the test did not see it because it only
        // ran the default set.
        let spec = Spec {
            length: 4,
            upper: false,
            lower: false,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            symbols_inside_only: true,
        };
        for _ in 0..200 {
            match password(&spec) {
                Ok(p) => {
                    let first = p.chars().next().expect("the first character");
                    let last = p.chars().last().expect("the last character");
                    assert!(!SYMBOLS.contains(first) && !SYMBOLS.contains(last), "punctuation on an edge: {p}");
                }
                Err(e) => assert!(e.starts_with("err.generator"), "an unexpected error: {e}"),
            }
        }
    }

    #[test]
    fn punctuation_only_and_clean_edges_do_not_go_together() {
        let spec = Spec {
            upper: false,
            lower: false,
            digits: false,
            symbols: true,
            symbols_inside_only: true,
            ..Spec::default()
        };
        assert!(password(&spec).is_err());
    }

    #[test]
    fn two_passwords_in_a_row_do_not_match() {
        let spec = Spec::default();
        assert_ne!(password(&spec).expect("the first"), password(&spec).expect("the second"));
    }
}
