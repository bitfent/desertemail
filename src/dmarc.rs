//! DMARC evaluation (RFC 7489 core subset).
//! Organizational domain uses a small hardcoded multi-level TLD list
//! (not a full Public Suffix List — documented limitation).

use crate::dkim::{DkimResult, DkimStatus};
use crate::dns;
use crate::spf::SpfResult;

/// DMARC policy from the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

impl DmarcPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            DmarcPolicy::None => "none",
            DmarcPolicy::Quarantine => "quarantine",
            DmarcPolicy::Reject => "reject",
        }
    }
}

/// Alignment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignMode {
    Relaxed,
    Strict,
}

/// Result of DMARC evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcResult {
    /// Whether DMARC authentication+alignment passed.
    pub pass: bool,
    /// Requested policy (p= or sp= as applicable).
    pub policy: DmarcPolicy,
    /// Disposition suggestion for the MTA: "none" | "quarantine" | "reject"
    /// (policy only applied when pass==false; when pass, disposition is none).
    pub disposition: DmarcPolicy,
    /// pct= from record (0-100); MTA may ignore for simplicity.
    pub pct: u8,
    /// True if a DMARC record was found.
    pub record_found: bool,
    /// Human-readable detail for Authentication-Results.
    pub detail: String,
}

impl DmarcResult {
    pub fn as_ar_result(&self) -> &'static str {
        if !self.record_found {
            "none"
        } else if self.pass {
            "pass"
        } else {
            "fail"
        }
    }
}

/// Evaluate DMARC for the RFC5322.From domain.
pub fn evaluate(
    from_header_domain: &str,
    spf_result: SpfResult,
    spf_domain: &str,
    dkim_results: &[DkimResult],
) -> DmarcResult {
    evaluate_with_lookup(from_header_domain, spf_result, spf_domain, dkim_results, |name| {
        dns::resolve_txt(name).ok()
    })
}

/// Injectable TXT lookup for tests.
pub fn evaluate_with_lookup<F>(
    from_header_domain: &str,
    spf_result: SpfResult,
    spf_domain: &str,
    dkim_results: &[DkimResult],
    mut txt_lookup: F,
) -> DmarcResult
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    let from_dom = from_header_domain.trim_end_matches('.').to_lowercase();
    if from_dom.is_empty() {
        return DmarcResult {
            pass: false,
            policy: DmarcPolicy::None,
            disposition: DmarcPolicy::None,
            pct: 100,
            record_found: false,
            detail: "no From domain".into(),
        };
    }

    let org = organizational_domain(&from_dom);
    // Try _dmarc.<from> then _dmarc.<org>
    let names = if from_dom == org {
        vec![format!("_dmarc.{}", from_dom)]
    } else {
        vec![
            format!("_dmarc.{}", from_dom),
            format!("_dmarc.{}", org),
        ]
    };

    let mut record: Option<String> = None;
    for n in &names {
        if let Some(txts) = txt_lookup(n) {
            if let Some(r) = find_dmarc_record(&txts) {
                record = Some(r);
                break;
            }
        }
    }

    let rec = match record {
        Some(r) => r,
        None => {
            return DmarcResult {
                pass: false,
                policy: DmarcPolicy::None,
                disposition: DmarcPolicy::None,
                pct: 100,
                record_found: false,
                detail: "no DMARC record".into(),
            };
        }
    };

    let tags = parse_dmarc_tags(&rec);
    let p = parse_policy(tags.get("p").map(|s| s.as_str()).unwrap_or("none"));
    let sp = tags
        .get("sp")
        .map(|s| parse_policy(s))
        .unwrap_or(p);
    let adkim = parse_align(tags.get("adkim").map(|s| s.as_str()).unwrap_or("r"));
    let aspf = parse_align(tags.get("aspf").map(|s| s.as_str()).unwrap_or("r"));
    let pct = tags
        .get("pct")
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(100)
        .min(100);

    // Subdomain of org domain uses sp= when From is not the org domain itself
    let policy = if from_dom == org { p } else { sp };

    // SPF alignment: SPF must Pass and domains align
    let spf_aligned = spf_result == SpfResult::Pass
        && domains_align(&from_dom, spf_domain, aspf);

    // DKIM alignment: any passing signature with aligned d=
    let dkim_aligned = dkim_results.iter().any(|d| {
        d.status == DkimStatus::Pass && domains_align(&from_dom, &d.domain, adkim)
    });

    let pass = spf_aligned || dkim_aligned;
    let disposition = if pass {
        DmarcPolicy::None
    } else {
        policy
    };

    let detail = format!(
        "dmarc={} policy={} spf_aligned={} dkim_aligned={}",
        if pass { "pass" } else { "fail" },
        policy.as_str(),
        spf_aligned,
        dkim_aligned
    );

    DmarcResult {
        pass,
        policy,
        disposition,
        pct,
        record_found: true,
        detail,
    }
}

pub fn find_dmarc_record(txts: &[String]) -> Option<String> {
    for t in txts {
        let trimmed = t.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("v=dmarc1") {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn parse_dmarc_tags(record: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in record.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(eq) = part.find('=') {
            let k = part.get(..eq).unwrap_or("").trim().to_ascii_lowercase();
            let v = part.get(eq + 1..).unwrap_or("").trim().to_string();
            map.insert(k, v);
        }
    }
    map
}

fn parse_policy(s: &str) -> DmarcPolicy {
    match s.to_ascii_lowercase().as_str() {
        "quarantine" => DmarcPolicy::Quarantine,
        "reject" => DmarcPolicy::Reject,
        _ => DmarcPolicy::None,
    }
}

fn parse_align(s: &str) -> AlignMode {
    match s.to_ascii_lowercase().as_str() {
        "s" => AlignMode::Strict,
        _ => AlignMode::Relaxed,
    }
}

/// Domain alignment check.
pub fn domains_align(from_domain: &str, auth_domain: &str, mode: AlignMode) -> bool {
    let from = from_domain.trim_end_matches('.').to_lowercase();
    let auth = auth_domain.trim_end_matches('.').to_lowercase();
    if from.is_empty() || auth.is_empty() {
        return false;
    }
    match mode {
        AlignMode::Strict => from == auth,
        AlignMode::Relaxed => {
            if from == auth {
                return true;
            }
            organizational_domain(&from) == organizational_domain(&auth)
        }
    }
}

/// Approximate registrable/organizational domain.
///
/// **Limitation:** not a full Public Suffix List. Treats the last two labels as
/// the registrable domain, except for a short hardcoded list of multi-level TLDs
/// (e.g. `co.uk`, `com.au`) where the last *three* labels form the org domain.
/// Exotic or new multi-part suffixes may be wrong — good enough for common mail.
pub fn organizational_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return domain;
    }
    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return domain;
    }
    // Check multi-level TLD: last two labels in the list
    let last_two = format!(
        "{}.{}",
        labels[labels.len() - 2],
        labels[labels.len() - 1]
    );
    if is_multi_level_tld(&last_two) {
        // org = last three labels
        if labels.len() >= 3 {
            return labels[labels.len() - 3..].join(".");
        }
    }
    // default: last two labels
    labels[labels.len() - 2..].join(".")
}

/// Hardcoded multi-level public suffixes (incomplete on purpose).
fn is_multi_level_tld(s: &str) -> bool {
    matches!(
        s,
        "co.uk"
            | "org.uk"
            | "ac.uk"
            | "gov.uk"
            | "me.uk"
            | "net.uk"
            | "com.au"
            | "net.au"
            | "org.au"
            | "edu.au"
            | "co.nz"
            | "net.nz"
            | "org.nz"
            | "co.jp"
            | "or.jp"
            | "ne.jp"
            | "com.br"
            | "com.mx"
            | "co.za"
            | "com.sg"
            | "com.hk"
            | "co.in"
            | "com.tw"
            | "co.kr"
            | "com.ar"
            | "com.tr"
            | "co.id"
            | "com.my"
            | "co.th"
            | "com.ph"
            | "com.vn"
            | "co.il"
            | "com.eg"
            | "com.ng"
            | "com.pk"
            | "com.sa"
            | "com.ua"
            | "com.pl"
            | "co.at"
            | "or.at"
            | "ac.at"
            | "gv.at"
            | "priv.at"
            | "com.cn"
            | "net.cn"
            | "org.cn"
            | "com.ru"
            | "net.ru"
            | "org.ru"
            | "co.ve"
            | "com.ve"
            | "gen.tr"
            | "org.tr"
            | "blogspot.com" // common multi-label "suffix" for mail From quirks
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::{DkimResult, DkimStatus};

    #[test]
    fn org_domain_simple() {
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.example.com"), "example.com");
    }

    #[test]
    fn org_domain_co_uk() {
        assert_eq!(organizational_domain("mail.foo.co.uk"), "foo.co.uk");
        assert_eq!(organizational_domain("foo.co.uk"), "foo.co.uk");
    }

    #[test]
    fn align_relaxed() {
        assert!(domains_align(
            "mail.example.com",
            "example.com",
            AlignMode::Relaxed
        ));
        assert!(!domains_align(
            "mail.example.com",
            "example.com",
            AlignMode::Strict
        ));
        assert!(domains_align(
            "example.com",
            "example.com",
            AlignMode::Strict
        ));
    }

    #[test]
    fn dmarc_pass_via_spf() {
        let r = evaluate_with_lookup(
            "example.com",
            SpfResult::Pass,
            "example.com",
            &[],
            |_| {
                Some(vec!["v=DMARC1; p=reject; adkim=r; aspf=r".into()])
            },
        );
        assert!(r.pass);
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.disposition, DmarcPolicy::None);
    }

    #[test]
    fn dmarc_fail_reject_policy() {
        let r = evaluate_with_lookup(
            "example.com",
            SpfResult::Fail,
            "evil.com",
            &[],
            |_| Some(vec!["v=DMARC1; p=reject".into()]),
        );
        assert!(!r.pass);
        assert_eq!(r.disposition, DmarcPolicy::Reject);
    }

    #[test]
    fn dmarc_pass_via_dkim() {
        let dkim = vec![DkimResult {
            status: DkimStatus::Pass,
            domain: "example.com".into(),
            selector: "mail".into(),
            detail: "ok".into(),
        }];
        let r = evaluate_with_lookup(
            "news.example.com",
            SpfResult::Fail,
            "other.com",
            &dkim,
            |_| Some(vec!["v=DMARC1; p=quarantine; adkim=r".into()]),
        );
        assert!(r.pass);
    }

    #[test]
    fn dmarc_no_record() {
        let r = evaluate_with_lookup("example.com", SpfResult::Pass, "example.com", &[], |_| {
            None
        });
        assert!(!r.record_found);
        assert_eq!(r.as_ar_result(), "none");
    }
}
