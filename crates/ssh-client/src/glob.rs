//! Matching host names against ssh_config-style patterns: `*` is any run of
//! characters, `?` is one character. Case is ignored, because host names are
//! case-insensitive.

/// Does `text` match the pattern `pattern`?
pub fn matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    is_match(&p, &t)
}

fn is_match(p: &[char], t: &[char]) -> bool {
    // An iterative algorithm that remembers the position of the last `*`:
    // linear in the length of the input and free of recursion, so pathological
    // patterns do not tear it apart.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Back up: the last `*` eats one more character.
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The number of literal (non-wildcard) characters in a pattern: a measure of
/// how specific the pattern is.
pub fn literal_len(pattern: &str) -> usize {
    pattern.chars().filter(|c| *c != '*' && *c != '?').count()
}

/// Does the pattern hold any wildcards?
pub fn has_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(matches("git.example.com", "Git.Example.COM"));
        assert!(!matches("git.example.com", "git.example.net"));
    }

    #[test]
    fn star_matches_subdomains() {
        assert!(matches("*.example.net", "node1.example.net"));
        assert!(matches("*.example.net", "a.b.example.net"));
        assert!(!matches("*.example.net", "example.net"));
    }

    #[test]
    fn question_matches_single_char() {
        assert!(matches("node?.example.net", "node1.example.net"));
        assert!(!matches("node?.example.net", "node12.example.net"));
    }

    #[test]
    fn bare_star_matches_everything() {
        assert!(matches("*", "anything.at.all"));
    }

    #[test]
    fn multiple_stars_do_not_backtrack_wrongly() {
        assert!(matches("*.dev.*.net", "a.dev.b.net"));
        assert!(!matches("*.dev.*.net", "a.prod.b.net"));
    }

    #[test]
    fn literal_len_counts_only_literals() {
        assert_eq!(literal_len("*.example.net"), 12);
        assert_eq!(literal_len("*"), 0);
    }

    // -- Edge cases, added by the red team --------------------------------

    #[test]
    fn star_crosses_dots_so_short_suffix_patterns_are_dangerously_wide() {
        // `*` does not stop at a dot. The pattern `*.com` is not "a
        // second-level domain" but "anything ending in .com": a key will travel
        // to any stranger's host in the zone.
        assert!(matches("*.com", "a.b.c.attacker.com"));
        assert!(matches("*", "any.host"));
        // Especially treacherous with no dot: the suffix sticks to somebody
        // else's name.
        assert!(matches("*example.com", "notexample.com"));
    }

    #[test]
    fn unicode_case_is_not_folded() {
        // DEFECT: to_ascii_lowercase does not touch anything outside ASCII.
        // Host names are case-insensitive throughout, and here only in latin.
        assert!(matches("GIT.EXAMPLE.COM", "git.example.com"));
        assert!(!matches("MÜNCHEN.example.com", "münchen.example.com"));
    }

    #[test]
    fn punycode_and_unicode_are_different_strings() {
        // DEFECT: ssh gives %h as it was typed. One and the same host, written
        // two ways, will not match itself.
        assert!(!matches("xn--mnchen-3ya.example.com", "münchen.example.com"));
        assert!(!matches("münchen.example.com", "xn--mnchen-3ya.example.com"));
    }

    #[test]
    fn trailing_dot_fqdn_does_not_match() {
        // DEFECT: `ssh git.example.com.` is a lawful way to write an absolute
        // name, and it silently misses the mapping.
        assert!(!matches("git.example.com", "git.example.com."));
        assert!(!matches("*.example.com", "a.example.com."));
    }

    #[test]
    fn empty_inputs_behave_predictably() {
        assert!(matches("", ""));
        assert!(!matches("", "a"));
        assert!(!matches("a", ""));
        // An empty host falls under a star, and ssh can pass an empty %h.
        assert!(matches("*", ""));
        assert!(matches("**", ""));
    }

    #[test]
    fn star_matches_empty_run_in_the_middle() {
        assert!(matches("a*b", "ab"));
        assert!(matches("a*b*c", "abc"));
    }

    #[test]
    fn pathological_pattern_does_not_blow_up() {
        // The classic exponential input for naive backtracking. The algorithm
        // is linear and so has to answer instantly.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(4096);
        let start = std::time::Instant::now();
        assert!(!matches(pattern, &text));
        assert!(start.elapsed().as_secs() < 2, "the matching went exponential");
    }

    #[test]
    fn literal_len_counts_chars_not_bytes() {
        // This matters when comparing specificity: otherwise a pattern outside
        // ASCII would beat a latin one twice over.
        assert_eq!(literal_len("münchen"), 7);
        assert_eq!(literal_len("?*?*"), 0);
    }

    #[test]
    fn has_wildcard_sees_both_metacharacters() {
        assert!(has_wildcard("a?b"));
        assert!(has_wildcard("a*b"));
        assert!(!has_wildcard("a-b_c.d"));
    }
}
