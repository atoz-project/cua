// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! The evidence of a machine that never came online: its console or serial
//! log, fetched before the failed create deletes the machine, filtered of
//! anything secret, kept under `<cua home>/cloud/boot-logs/<id>.log` (0600),
//! and summarized in the error the person sees.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the cloud gets to hand over the log. The rollback never waits
/// longer, whatever the cloud does.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Lines kept in the saved file (the end of the log: the failure is there).
pub const KEEP_LINES: usize = 200;

/// Lines quoted in the error.
pub const SHOW_LINES: usize = 10;

/// Words that make a line secret: the relay token (`cmt_...`), any token,
/// secret, password, key or credential, and the guest environment file. The
/// guest's own log filter (`bootstrap`) hides `token` and `cmt_`; this adds
/// the rest, because a console log also carries the kernel and cloud-init.
const SECRET_WORDS: &[&str] = &[
    "token",
    "cmt_",
    "secret",
    "password",
    "passwd",
    "bearer",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "private key",
    "credential",
    "sandbox.env",
    "spacesd.env",
    "jwks",
];

/// A secret value shorter than this is not matched as a value (it would
/// hide ordinary words).
const MIN_SECRET_LEN: usize = 8;

/// URL query parameters that commonly carry pre-signed credentials or tokens.
const URL_QUERY_SECRET_PARAMS: &[&str] = &[
    "?sig=",
    "&sig=",
    "?signature=",
    "&signature=",
    "x-amz-signature=",
    "x-amz-credential=",
    "x-amz-security-token=",
    "x-goog-signature=",
    "x-goog-credential=",
    "x-goog-algorithm=",
    "googleaccessid=",
    "ossaccesskeyid=",
    "x-oss-signature=",
    "x-oss-security-token=",
    "x-oss-credential=",
    "awsaccesskeyid=",
    "?sas=",
    "&sas=",
    "?auth=",
    "&auth=",
    "?key=",
    "&key=",
    "?hmac=",
    "&hmac=",
];

fn contains_url_secret(low: &str) -> bool {
    URL_QUERY_SECRET_PARAMS.iter().any(|p| low.contains(p))
}

fn strip_escapes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if !c.is_control() || c == '\t' {
            out.push(c);
        }
    }
    out
}

fn scrub_path_and_sha256(rest_of_token: &str) -> String {
    let path = rest_of_token.split(['?', '#']).next().unwrap_or("");
    let mut out = String::from(path);
    if let Some((_, frag)) = rest_of_token.split_once('#')
        && let Some(hex) = frag.strip_prefix("sha256=")
        && !hex.is_empty()
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        out.push('#');
        out.push_str(frag);
    }
    out
}

fn next_url_scheme_start(after_token: &str) -> Option<usize> {
    let sep = after_token.find("://")?;
    let bytes = after_token.as_bytes();
    let mut start = sep;
    while start > 0 {
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
            start -= 1;
        } else {
            break;
        }
    }
    Some(start)
}

fn scrub_line_urls(line: &str) -> Option<String> {
    use cua_sandbox_core::byoc::{is_qualified_host, is_valid_host_or_hostport};

    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(idx) = rest.find("://") {
        let before_sep = &rest[..idx];
        let scheme = before_sep
            .rsplit_once(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '+' | '-' | '.'))
            .map_or(before_sep, |(_, s)| s);
        out.push_str(&rest[..idx + 3]);
        let after_scheme = &rest[idx + 3..];
        let token_end = after_scheme
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>'))
            .unwrap_or(after_scheme.len());
        let mut body_end = token_end;
        while body_end > 0 {
            let b = after_scheme.as_bytes()[body_end - 1];
            let slice = &after_scheme[..body_end];
            if matches!(b, b',' | b')' | b';')
                || (b == b']' && (!slice.starts_with('[') || slice.contains(['/', '?', '#'])))
            {
                body_end -= 1;
            } else {
                break;
            }
        }
        let url_body = &after_scheme[..body_end];
        let after_token = &after_scheme[body_end..];
        let auth_end = url_body.find(['/', '?', '#']).unwrap_or(url_body.len());
        let raw_auth = &url_body[..auth_end];
        let rest_of_token = &url_body[auth_end..];

        let gap = match next_url_scheme_start(after_token) {
            Some(n) => &after_token[..n],
            None => after_token,
        };
        for w in gap.split_whitespace() {
            let wt = w.trim_matches(|c: char| {
                matches!(
                    c,
                    '\'' | '"' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';'
                )
            });
            if wt.starts_with('@')
                || wt.contains("/@")
                || wt
                    .split_once('@')
                    .is_some_and(|(_, tail)| tail.contains(['/', '?', '#']))
                || (!rest_of_token.starts_with('/')
                    && !is_qualified_host(raw_auth)
                    && wt.contains('@'))
            {
                return None;
            }
        }

        if raw_auth.is_empty() {
            if rest_of_token.is_empty() {
                rest = after_token;
                continue;
            }
            if matches!(scheme.to_ascii_lowercase().as_str(), "file" | "unix")
                && rest_of_token.starts_with('/')
                && !rest_of_token.contains('@')
            {
                out.push_str(&scrub_path_and_sha256(rest_of_token));
                rest = after_token;
                continue;
            }
            return None;
        } else if let Some((_, host_candidate)) = raw_auth.rsplit_once('@') {
            if !is_valid_host_or_hostport(host_candidate) {
                return None;
            }
            if !rest_of_token.starts_with('/') && rest_of_token.contains('@') {
                return None;
            }
            if rest_of_token.starts_with("/@")
                && host_candidate.contains(':')
                && !is_qualified_host(host_candidate)
            {
                return None;
            }
            out.push_str("<redacted>@");
            out.push_str(host_candidate);
            out.push_str(&scrub_path_and_sha256(rest_of_token));
        } else {
            if !is_valid_host_or_hostport(raw_auth) {
                return None;
            }
            if !rest_of_token.starts_with('/') && rest_of_token.contains('@') {
                return None;
            }
            if rest_of_token.contains('@') && raw_auth.contains(':') && !is_qualified_host(raw_auth)
            {
                return None;
            }
            out.push_str(raw_auth);
            out.push_str(&scrub_path_and_sha256(rest_of_token));
        }
        rest = after_token;
    }
    out.push_str(rest);
    Some(out)
}

/// The last [`KEEP_LINES`] lines of `raw` without any line that mentions a
/// secret word or one of the `secrets` values themselves, with URL userinfo
/// credentials scrubbed.
pub fn filter(raw: &str, secrets: &[&str]) -> Vec<String> {
    let secrets: Vec<&str> = secrets
        .iter()
        .copied()
        .filter(|s| s.len() >= MIN_SECRET_LEN)
        .collect();
    let mut lines: Vec<String> = raw
        .lines()
        .map(strip_escapes)
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            !SECRET_WORDS.iter().any(|w| low.contains(w))
                && !contains_url_secret(&low)
                && !secrets.iter().any(|s| l.contains(s))
        })
        .filter_map(|l| scrub_line_urls(&l))
        .collect();
    let drop = lines.len().saturating_sub(KEEP_LINES);
    lines.drain(..drop);
    lines
}

/// `id` as a file name.
fn file_name(id: &str) -> String {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{}.log", safe.trim_start_matches('.'))
}

/// Where `id`'s boot log is kept under `home`.
pub fn path_of(home: &Path, id: &str) -> PathBuf {
    home.join("cloud").join("boot-logs").join(file_name(id))
}

/// Writes `lines` to the boot log of `id` (0600) and returns its path.
pub fn save(home: &Path, id: &str, lines: &[String]) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    let path = path_of(home, id);
    let dir = path.parent().expect("boot log dir");
    std::fs::create_dir_all(dir)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    for l in lines {
        writeln!(f, "{l}")?;
    }
    Ok(path)
}

/// What the error adds: where the log is and its last [`SHOW_LINES`] lines.
pub fn summary(path: Option<&Path>, lines: &[String]) -> String {
    let mut s = String::new();
    match path {
        Some(p) => s.push_str(&format!("boot log saved to {}", p.display())),
        None => s.push_str("boot log (could not be saved)"),
    }
    let from = lines.len().saturating_sub(SHOW_LINES);
    s.push_str(", last lines:");
    for l in &lines[from..] {
        s.push_str("\n  ");
        s.push_str(l);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_noise_are_dropped_and_the_end_is_kept() {
        let mut raw = String::new();
        for i in 0..300 {
            raw.push_str(&format!("\u{1b}[0;32mline {i}\u{1b}[0m\r\n"));
        }
        raw.push_str("relay token cmt_abcdef0123 joined\n");
        raw.push_str("Authorization: Bearer abc\n");
        raw.push_str("value hunter2hunter2 leaked\n");
        raw.push_str("downloading https://u:p@mirror.example.com/cua.exe\n");
        raw.push_str("GET https://bucket.example.com/cua.exe?sig=Short1&other=1\n");
        raw.push_str("last ok line\n\n");
        let out = filter(&raw, &["hunter2hunter2", "x"]);
        assert_eq!(out.len(), KEEP_LINES);
        assert_eq!(out.last().unwrap(), "last ok line");
        assert!(out.iter().all(|l| !l.contains("cmt_")
            && !l.contains("Bearer")
            && !l.contains("hunter2")
            && !l.contains("u:p@")
            && !l.contains("sig=Short1")
            && !l.contains('\u{1b}')));
        assert!(out.contains(&"line 299".to_string()));
    }

    #[test]
    fn saved_privately_and_summarized() {
        let dir = tempfile::tempdir().unwrap();
        let lines: Vec<String> = (0..30).map(|i| format!("l{i}")).collect();
        let p = save(dir.path(), "../i-0abc", &lines).unwrap();
        assert!(p.starts_with(dir.path().join("cloud/boot-logs")));
        assert_eq!(p.file_name().unwrap(), "_i-0abc.log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let s = summary(Some(&p), &lines);
        assert!(
            s.contains("l29") && s.contains("l20") && !s.contains("l19"),
            "{s}"
        );
        assert!(s.contains(&p.display().to_string()));
    }

    #[test]
    fn spacesd_env_and_url_userinfo_are_redacted() {
        let raw = "\
boot step 1 ok\n\
chmod 0600 /etc/cua/spacesd.env\n\
downloading cua-spacesd from https://user:s3cr3t@mirror.example.com/cua-spacesd.tar.gz\n\
also https://user:secret@mirror.example.com/cua-spacesd.tar.gz\n\
fallback http://tok:p4ssw0rd@127.0.0.1:8080/cua-spacesd failed\n\
mirror https://mirror.example.com/@cua/cua-spacesd.tar.gz ok\n\
owner ada@example.com done\n";
        let out = filter(raw, &[]);
        assert!(
            out.iter().all(|l| !l.contains("spacesd.env")),
            "spacesd.env line leaked: {out:?}"
        );
        assert!(
            out.iter()
                .all(|l| !l.contains("s3cr3t") && !l.contains("p4ssw0rd") && !l.contains("secret")),
            "URL password leaked: {out:?}"
        );
        assert!(
            out.iter()
                .all(|l| !l.contains("user:") && !l.contains("tok:")),
            "URL username leaked: {out:?}"
        );
        assert!(
            out.iter()
                .any(|l| l.contains("https://<redacted>@mirror.example.com/cua-spacesd.tar.gz")),
            "expected redacted https URL in {out:?}"
        );
        assert!(
            out.iter()
                .any(|l| l.contains("http://<redacted>@127.0.0.1:8080/cua-spacesd")),
            "expected redacted http URL in {out:?}"
        );
        assert!(
            out.iter()
                .any(|l| l.contains("https://mirror.example.com/@cua/cua-spacesd.tar.gz")),
            "valid @ path corrupted: {out:?}"
        );
        assert!(
            out.iter().any(|l| l.contains("ada@example.com")),
            "plain email corrupted: {out:?}"
        );
    }

    #[test]
    fn url_userinfo_with_backslash_before_at_is_redacted() {
        let raw = "\
downloading from https://user:8443\\@mirror.example.com/bin failed\n\
downloading from https://s3cr3t\\@mirror.example.com/bin failed\n\
mirror https://mirror.example.com/@cua/cua-spacesd.tar.gz ok\n";
        let out = filter(raw, &[]);
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(
            out.iter()
                .all(|l| !l.contains("8443") && !l.contains("user:") && !l.contains("s3cr3t")),
            "URL credentials leaked with backslash before @: {out:?}"
        );
        assert_eq!(
            out[0],
            "downloading from https://<redacted>@mirror.example.com/bin failed"
        );
        assert_eq!(
            out[1],
            "downloading from https://<redacted>@mirror.example.com/bin failed"
        );
        assert_eq!(
            out[2],
            "mirror https://mirror.example.com/@cua/cua-spacesd.tar.gz ok"
        );
    }

    #[test]
    fn structural_url_scrubbing_blocks_bypasses_and_preserves_legitimate_lines() {
        for (line, forbidden) in [
            (
                "downloading https://user:p4ssw0rd?@evil.com/bin",
                &["user", "p4ssw0rd"][..],
            ),
            (
                "downloading https://user:p4ssw0rd#@evil.com/bin",
                &["user", "p4ssw0rd"][..],
            ),
            (
                "downloading https://user:p4ssw0rd foo/@evil.com/bin",
                &["user", "p4ssw0rd", "foo/"][..],
            ),
            (
                "downloading https://user:p4ssw0rd @evil.com/bin",
                &["user", "p4ssw0rd"][..],
            ),
            (
                "downloading https://user:8080?x=@evil.com/bin",
                &["user", "8080"][..],
            ),
            (
                "downloading https://user:8080#@evil.com/bin",
                &["user", "8080"][..],
            ),
            (
                "downloading https://user:8080 foo/@evil.com/bin",
                &["user", "8080", "foo/"][..],
            ),
            (
                "downloading https://user:123456#@evil.com/bin",
                &["user", "123456"][..],
            ),
            (
                "downloading https://user:123456?x=@evil.com/bin",
                &["user", "123456"][..],
            ),
            (
                "downloading https://user:p4ssw0rd%40evil.com/bin",
                &["user", "p4ssw0rd"][..],
            ),
            (
                "downloading https://ada@org:p4ssw0rd/@evil.com/bin",
                &["ada", "org", "p4ssw0rd"][..],
            ),
            (
                "downloading https://ada@org:8080/@evil.com/bin",
                &["ada", "org", "8080"][..],
            ),
            (
                "downloading https://mirror.example.com/bin?X-Goog-Signature=GOOG9988",
                &["GOOG9988"][..],
            ),
            (
                "GET /bin?X-Goog-Signature=GOOG9988 HTTP/1.1",
                &["GOOG9988"][..],
            ),
            (
                "GET /bin?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE HTTP/1.1",
                &["AKIAIOSFODNN7EXAMPLE"][..],
            ),
            (
                "downloading https://mirror.example.com/bin?X-Custom-Auth=CUST9988",
                &["CUST9988"][..],
            ),
        ] {
            let out = filter(line, &[]);
            for bad in forbidden {
                assert!(
                    out.iter().all(|l| !l.contains(bad)),
                    "leaked {bad:?} for {line:?}: {out:?}"
                );
            }
        }

        assert_eq!(
            filter("downloading https://ada@org:p4ssw0rd@evil.com/bin", &[]),
            vec!["downloading https://<redacted>@evil.com/bin"]
        );

        let sha = "0123456789abcdef".repeat(4);
        for ok in [
            "downloading https://example.com/@org/cua-spacesd".to_string(),
            "downloading https://mirror.example.com/bin".to_string(),
            "fallback http://localhost:8080/@cua/cua-spacesd ok".to_string(),
            "owner ops@example.com done".to_string(),
            "downloading https://mirror.example.com/bin contact ops@example.com".to_string(),
            "socket unix:///var/run/docker.sock ready".to_string(),
            format!("downloading https://mirror.example.com/bin#sha256={sha}"),
        ] {
            assert_eq!(filter(&ok, &[]), vec![ok.clone()], "corrupted {ok:?}");
        }

        assert_eq!(
            filter(
                "first https://u:p@a.com/bin second https://b.com/@org/bin",
                &[]
            ),
            vec!["first https://<redacted>@a.com/bin second https://b.com/@org/bin"]
        );
    }
}
