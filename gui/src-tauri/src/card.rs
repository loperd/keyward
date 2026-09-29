//! Telling the fields of a payment form apart, and what goes into each: no
//! Accessibility here, only words and numbers, so it can be tested.

/// Which part of a card a field of a payment form asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardSlot {
    Number,
    Code,
    Holder,
    /// The month and the year in one field; `long` when it wants the year in
    /// four digits.
    Expiry { long: bool },
    Month,
    /// `short` when it wants the year in two digits.
    Year { short: bool },
}

/// Tell a field of a payment form by its captions: the label, the
/// placeholder, the page's `id`. Somebody else's page again, so the words
/// are not ours to translate — the same reasoning as for the words above.
/// `None` for a field that is not part of a card.
pub fn card_slot(captions: &str) -> Option<CardSlot> {
    let low = captions.to_lowercase();
    let toks: Vec<&str> = low.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).collect();
    let tok = |words: &[&str]| words.iter().any(|w| toks.contains(w));
    let sub = |words: &[&str]| words.iter().any(|w| low.contains(w));
    if tok(&["cvc", "cvv", "cvc2", "cvv2", "csc", "cvn"])
        || sub(&["security code", "securitycode", "card code", "\u{43a}\u{43e}\u{434} \u{431}\u{435}\u{437}\u{43e}\u{43f}"])
    {
        return Some(CardSlot::Code);
    }
    // мм, месяц / гг, гггг, год / срок
    let month = tok(&["mm", "month", "\u{43c}\u{43c}", "\u{43c}\u{435}\u{441}\u{44f}\u{446}"]) || sub(&["expmonth"]);
    let year = tok(&["yy", "yyyy", "year", "\u{433}\u{433}", "\u{433}\u{433}\u{433}\u{433}", "\u{433}\u{43e}\u{434}"]) || sub(&["expyear"]);
    let expiry = tok(&["exp", "expiry", "expiration", "expires", "\u{441}\u{440}\u{43e}\u{43a}"]) || sub(&["expir", "expdate", "valid thru", "valid until"]);
    let long = tok(&["yyyy", "\u{433}\u{433}\u{433}\u{433}"]);
    if (month && year) || (expiry && !month && !year) {
        return Some(CardSlot::Expiry { long });
    }
    if month {
        return Some(CardSlot::Month);
    }
    if year {
        return Some(CardSlot::Year { short: tok(&["yy", "\u{433}\u{433}"]) });
    }
    // A placeholder that draws a number in groups says it plainly.
    if (tok(&["card"]) && tok(&["number", "no", "num"]))
        || sub(&["cardnumber", "cc-number", "ccnumber", "\u{43d}\u{43e}\u{43c}\u{435}\u{440} \u{43a}\u{430}\u{440}\u{442}", "1234 1234", "0000 0000", "\u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022}"])
    {
        return Some(CardSlot::Number);
    }
    // владел(ец), имя на карте
    if tok(&["cardholder", "holder"])
        || sub(&["name on card", "nameoncard", "cc-name", "ccname", "\u{432}\u{43b}\u{430}\u{434}\u{435}\u{43b}", "\u{438}\u{43c}\u{44f} \u{43d}\u{430} \u{43a}\u{430}\u{440}\u{442}"])
    {
        return Some(CardSlot::Holder);
    }
    None
}

/// Does a drop-down list's item mean this month? `03`, `3`, `03 - March`,
/// `March`, `Mar`, `март` all do.
pub fn month_matches(title: &str, month: u32) -> bool {
    const NAMES: [&[&str]; 12] = [
        &["jan", "\u{44f}\u{43d}\u{432}"],
        &["feb", "\u{444}\u{435}\u{432}"],
        &["mar", "\u{43c}\u{430}\u{440}"],
        &["apr", "\u{430}\u{43f}\u{440}"],
        &["may", "\u{43c}\u{430}\u{439}", "\u{43c}\u{430}\u{44f}"],
        &["jun", "\u{438}\u{44e}\u{43d}"],
        &["jul", "\u{438}\u{44e}\u{43b}"],
        &["aug", "\u{430}\u{432}\u{433}"],
        &["sep", "\u{441}\u{435}\u{43d}"],
        &["oct", "\u{43e}\u{43a}\u{442}"],
        &["nov", "\u{43d}\u{43e}\u{44f}"],
        &["dec", "\u{434}\u{435}\u{43a}"],
    ];
    let low = title.trim().to_lowercase();
    if let Some(n) = leading_number(&low) {
        return n == month;
    }
    (1..=12).contains(&month) && NAMES[month as usize - 1].iter().any(|n| low.starts_with(n))
}

/// Does a drop-down list's item mean this year? `2029` and `29` both do.
pub fn year_matches(title: &str, yyyy: u32) -> bool {
    match leading_number(title.trim()) {
        Some(n) if n >= 100 => n == yyyy,
        Some(n) => n == yyyy % 100,
        None => false,
    }
}

fn leading_number(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// The ways a month may be written in a list: `03`, `3`, `March`.
pub fn month_spellings(mm: &str) -> Vec<String> {
    const EN: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    let n: usize = mm.parse().unwrap_or(0);
    let mut out = vec![format!("{n:02}"), n.to_string()];
    if (1..=12).contains(&n) {
        out.push(EN[n - 1].to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_fields_are_told_apart_by_their_captions() {
        assert_eq!(card_slot("Card number · 1234 1234 1234 1234"), Some(CardSlot::Number));
        assert_eq!(card_slot("cardnumber"), Some(CardSlot::Number));
        assert_eq!(card_slot("Номер карты"), Some(CardSlot::Number));
        assert_eq!(card_slot("CVC"), Some(CardSlot::Code));
        assert_eq!(card_slot("Security code · 3 digits"), Some(CardSlot::Code));
        assert_eq!(card_slot("Expiration date · MM / YY"), Some(CardSlot::Expiry { long: false }));
        assert_eq!(card_slot("MM/YYYY"), Some(CardSlot::Expiry { long: true }));
        assert_eq!(card_slot("ММ/ГГ"), Some(CardSlot::Expiry { long: false }));
        assert_eq!(card_slot("Expiry month · cc-exp-month"), Some(CardSlot::Month));
        assert_eq!(card_slot("YY"), Some(CardSlot::Year { short: true }));
        assert_eq!(card_slot("Expiry year"), Some(CardSlot::Year { short: false }));
        assert_eq!(card_slot("Name on card"), Some(CardSlot::Holder));
        assert_eq!(card_slot("Cardholder name"), Some(CardSlot::Holder));
        assert_eq!(card_slot("Email"), None);
        assert_eq!(card_slot("Comment"), None);
        assert_eq!(card_slot("Password"), None);
    }

    #[test]
    fn list_items_are_matched_to_the_month_and_the_year() {
        assert!(month_matches("03", 3));
        assert!(month_matches("3", 3));
        assert!(month_matches("03 - March", 3));
        assert!(month_matches("March", 3));
        assert!(month_matches("Май", 5));
        assert!(!month_matches("12", 1));
        assert!(!month_matches("Month", 3));
        assert!(year_matches("2029", 2029));
        assert!(year_matches("29", 2029));
        assert!(!year_matches("2030", 2029));
        assert!(!year_matches("Year", 2029));
    }
}
