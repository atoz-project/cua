// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Structural HTTP(S) URL parsing and redaction shared across contract, core,
//! and wasm32-safe crates.

fn is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}

fn is_valid_ipv4_or_dns_host(host: &str) -> bool {
    if host.is_empty() || !host.is_ascii() {
        return false;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    let h = host.strip_suffix('.').unwrap_or(host);
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels_ok = h.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    labels_ok
        && !h
            .rsplit('.')
            .next()
            .unwrap_or(h)
            .bytes()
            .all(|b| b.is_ascii_digit())
}

/// Returns `true` when `auth` is a strict RFC-3986 `host` or `host:port`
/// (IPv4, bracketed IPv6, or ASCII DNS hostname, with optional `1..=65535` port
/// without leading `'0'`).
pub fn is_valid_host_or_hostport(auth: &str) -> bool {
    if auth.is_empty() || !auth.is_ascii() {
        return false;
    }
    if let Some(rest) = auth.strip_prefix('[') {
        let Some((ip, tail)) = rest.split_once(']') else {
            return false;
        };
        return ip.parse::<std::net::Ipv6Addr>().is_ok()
            && (tail.is_empty() || tail.strip_prefix(':').is_some_and(is_valid_port));
    }
    if auth.contains(['[', ']']) {
        return false;
    }
    match auth.split_once(':') {
        Some((host, port)) => is_valid_ipv4_or_dns_host(host) && is_valid_port(port),
        None => is_valid_ipv4_or_dns_host(auth),
    }
}

/// Returns `true` when `host_port` is a valid IPv4/IPv6 literal, `localhost`,
/// or a dotted domain name (as opposed to a bare single-label name such as
/// `user:8080`).
pub fn is_qualified_host(host_port: &str) -> bool {
    if !is_valid_host_or_hostport(host_port) {
        return false;
    }
    if host_port.starts_with('[') {
        return true;
    }
    let host = host_port.split_once(':').map_or(host_port, |(h, _)| h);
    host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        || host.contains('.')
}

/// Why [`parse_http_url`] rejected an input string.
pub enum UrlReject {
    BadChars,
    MissingScheme,
    UnsupportedScheme(String),
    Backslash,
    InvalidHostOrPort,
    UrlParse(url::ParseError),
    EmptyHost,
}

/// Parsed HTTP(S) URL with authority/delimiter ambiguity metadata.
pub struct ParsedHttpUrl<'a> {
    pub parsed: url::Url,
    pub raw_path: &'a str,
    pub has_userinfo: bool,
    pub multi_at: bool,
    pub ambiguous_at: bool,
}

/// Parses and structurally validates an ASCII HTTP(S) URL without leaking
/// secrets in scheme rejection errors.
pub fn parse_http_url(trimmed: &str) -> Result<ParsedHttpUrl<'_>, UrlReject> {
    if !trimmed.is_ascii()
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\'' | '"'))
    {
        return Err(UrlReject::BadChars);
    }
    let Some((scheme_raw, after_scheme)) = trimmed.split_once("://") else {
        return Err(UrlReject::MissingScheme);
    };
    // Require RFC 3986 scheme syntax (and bounded length) before treating the
    // prefix as a scheme so a malformed URL containing a later "://" in its
    // query or fragment never echoes URL contents into UnsupportedScheme.
    if scheme_raw.is_empty()
        || scheme_raw.len() > 16
        || !scheme_raw.as_bytes()[0].is_ascii_alphabetic()
        || !scheme_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(UrlReject::MissingScheme);
    }
    let scheme_lower = scheme_raw.to_ascii_lowercase();
    if !matches!(scheme_lower.as_str(), "http" | "https") {
        return Err(UrlReject::UnsupportedScheme(scheme_lower));
    }
    let delim = after_scheme
        .find(['/', '\\', '?', '#'])
        .unwrap_or(after_scheme.len());
    let (raw_authority, raw_tail) = after_scheme.split_at(delim);
    if raw_tail.starts_with('\\') {
        return Err(UrlReject::Backslash);
    }
    let at_count = raw_authority.bytes().filter(|&b| b == b'@').count();
    let has_userinfo = at_count > 0;
    let raw_hp = raw_authority
        .rsplit_once('@')
        .map_or(raw_authority, |(_, hp)| hp);
    if !is_valid_host_or_hostport(raw_hp) {
        return Err(UrlReject::InvalidHostOrPort);
    }
    let has_port = raw_hp.strip_prefix('[').map_or_else(
        || raw_hp.contains(':'),
        |r| r.split_once(']').is_some_and(|(_, t)| t.starts_with(':')),
    );
    let parsed = url::Url::parse(trimmed).map_err(UrlReject::UrlParse)?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(UrlReject::EmptyHost);
    }
    if parsed.port() == Some(0) {
        return Err(UrlReject::InvalidHostOrPort);
    }
    let qualified = is_qualified_host(raw_hp);
    let ambiguous_at = raw_tail.contains("?@")
        || raw_tail.contains("#@")
        || (raw_tail.contains('@')
            && ((has_port && !qualified)
                || (!raw_tail.starts_with('/') && (has_userinfo || !qualified))));
    let raw_path = if raw_tail.starts_with('/') {
        &raw_tail[..raw_tail.find(['?', '#']).unwrap_or(raw_tail.len())]
    } else {
        ""
    };
    Ok(ParsedHttpUrl {
        parsed,
        raw_path,
        has_userinfo,
        multi_at: at_count > 1,
        ambiguous_at,
    })
}

/// Strips URL userinfo (`user:pass@`), `?query` parameters, and non-`#sha256=`
/// fragments from `raw` so credentials and signed tokens never appear in logs,
/// error messages, or `Debug` output.
pub fn redact_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Ok(u) = parse_http_url(trimmed) else {
        return "<redacted>".into();
    };
    if u.multi_at || u.ambiguous_at {
        return "<redacted>".into();
    }
    let Some(host) = u.parsed.host_str() else {
        return "<redacted>".into();
    };
    let mut out = match u.parsed.port() {
        Some(port) => format!("{}://{host}:{port}{}", u.parsed.scheme(), u.raw_path),
        None => format!("{}://{host}{}", u.parsed.scheme(), u.raw_path),
    };
    if let Some(frag) = u.parsed.fragment()
        && let Some(hex) = frag.strip_prefix("sha256=")
        && !hex.is_empty()
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        out.push('#');
        out.push_str(frag);
    }
    out
}
