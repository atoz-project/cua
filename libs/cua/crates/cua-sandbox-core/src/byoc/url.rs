// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! URL validation and redaction helpers for BYOC download mirrors and boot logs.

use crate::Result;
use cua_spaces_contract::url_redact::{UrlReject, parse_http_url};
pub use cua_spaces_contract::url_redact::{
    is_qualified_host, is_valid_host_or_hostport, redact_url,
};

/// Validates a custom `cua-spacesd` binary/archive download URL: must be
/// `https://`, loopback `http://` (`localhost` / `127.0.0.1` / `[::1]`), or
/// RFC 1918 private-IPv4 `http://`, without embedded URL userinfo
/// credentials, backslashes in authority, quotes, non-ASCII, or whitespace; an
/// optional `#sha256=<64 hex>` fragment is checked if present.
pub fn validate_spacesd_download_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(crate::Error::InvalidArgument(
            "--spacesd-download-url cannot be empty".into(),
        ));
    }
    let safe = redact_url(trimmed);
    let u = parse_http_url(trimmed).map_err(|rej| {
        let msg = match rej {
            UrlReject::BadChars => {
                format!(
                    "--spacesd-download-url {safe:?} must be an ASCII URL without whitespace or quotes"
                )
            }
            UrlReject::MissingScheme => {
                format!("--spacesd-download-url {safe:?}: missing URL scheme (use https://)")
            }
            UrlReject::UnsupportedScheme(other) => {
                format!("--spacesd-download-url scheme {other:?} is not supported (use https://)")
            }
            UrlReject::Backslash => {
                format!("--spacesd-download-url {safe:?} cannot contain '\\\\' in host")
            }
            UrlReject::EmptyHost => "--spacesd-download-url must include a host".into(),
            UrlReject::InvalidHostOrPort => {
                format!("--spacesd-download-url {safe:?} has an invalid host or port")
            }
            UrlReject::UrlParse(e) => format!("--spacesd-download-url {safe:?}: {e}"),
        };
        crate::Error::InvalidArgument(msg)
    })?;
    if u.has_userinfo
        || u.ambiguous_at
        || !u.parsed.username().is_empty()
        || u.parsed.password().is_some()
    {
        return Err(crate::Error::InvalidArgument(
            "--spacesd-download-url cannot include embedded username or password credentials"
                .into(),
        ));
    }
    let is_local_http = match u.parsed.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if u.parsed.scheme() == "http" && !is_local_http {
        return Err(crate::Error::InvalidArgument(format!(
            "--spacesd-download-url {safe:?}: use https:// (plain http is only allowed for localhost/127.0.0.1 or RFC1918 private IPs)"
        )));
    }
    if let Some(frag) = u.parsed.fragment()
        && let Some(hex) = frag.strip_prefix("sha256=")
        && (hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(crate::Error::InvalidArgument(format!(
            "--spacesd-download-url #sha256= fragment must be 64 hex characters (got {} chars)",
            hex.len()
        )));
    }
    Ok(trimmed.to_string())
}

/// Validates a `cua-spacesd` download URL for `os_family` (`windows`, `linux`,
/// `linux-slim`, ...): rejects directory mirrors paired with a single-file
/// `#sha256=` hash, and rejects obvious cross-OS artifact mismatches.
pub fn validate_spacesd_url_for_os(raw: &str, os_family: &str) -> std::result::Result<(), String> {
    let trimmed = validate_spacesd_download_url(raw).map_err(|e| e.to_string())?;
    let safe = redact_url(&trimmed);
    let (before_frag, frag) = trimmed
        .split_once('#')
        .map_or((trimmed.as_str(), None), |(b, f)| (b, Some(f)));
    let before_query = before_frag.split_once('?').map_or(before_frag, |(p, _)| p);
    let path = before_query
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or("")
        .to_ascii_lowercase();
    if path.ends_with('/') {
        if frag.is_some_and(|f| f.starts_with("sha256=")) {
            return Err(format!(
                "--spacesd-download-url {safe:?}: a directory mirror URL cannot carry a single-file #sha256= fragment; publish per-file .sha256 sidecars instead"
            ));
        }
        return Ok(());
    }
    let os = os_family.trim().to_ascii_lowercase();
    if os == "windows"
        && [
            ".tar.gz",
            ".tgz",
            ".tar.xz",
            "-linux-x86_64",
            "-linux-aarch64",
        ]
        .iter()
        .any(|s| path.ends_with(s))
    {
        return Err(format!(
            "--spacesd-download-url {safe:?} looks like a Linux artifact, which cannot run on Windows"
        ));
    }
    if os.starts_with("linux") && [".exe", ".msi"].iter().any(|s| path.ends_with(s)) {
        return Err(format!(
            "--spacesd-download-url {safe:?} looks like a Windows artifact, which cannot run on {os_family}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byoc::{CloudProvider, CloudTarget};

    #[test]
    fn redact_url_strips_userinfo_query_and_non_sha_fragments() {
        assert_eq!(
            redact_url(
                "https://dluser:MyPass998877@mirror.example.com:8443/cua-spacesd.exe?sig=DeadBeefCafe9988#sha256=abab"
            ),
            "https://mirror.example.com:8443/cua-spacesd.exe#sha256=abab"
        );
        assert_eq!(
            redact_url("https://mirror.example.com/cua.exe#token=secret"),
            "https://mirror.example.com/cua.exe"
        );
        assert_eq!(redact_url("https://user:pass@/cua.exe"), "<redacted>");

        let secret_url = "https://dluser:MyPass998877@mirror.example.com/cua.exe?sig=DeadBeefCafe9988#sha256=abab";
        let t_dbg = format!(
            "{:?}",
            CloudTarget {
                provider: "aliyun-ecs".into(),
                spacesd_download_url: Some(secret_url.into()),
                ..Default::default()
            }
        );
        let p_dbg = format!(
            "{:?}",
            CloudProvider {
                name: "aliyun-ecs".into(),
                spacesd_download_url: Some(secret_url.into()),
                ..Default::default()
            }
        );
        for dbg in [t_dbg, p_dbg] {
            assert!(!dbg.contains("MyPass998877"), "{dbg}");
            assert!(!dbg.contains("DeadBeefCafe9988"), "{dbg}");
            assert!(
                dbg.contains("https://mirror.example.com/cua.exe#sha256=abab"),
                "{dbg}"
            );
        }
    }

    #[test]
    fn spacesd_download_url_allows_https_and_loopback_or_private_http_only() {
        assert_eq!(
            validate_spacesd_download_url("  https://mirror.example.cn/cua/cua-spacesd.tar.gz  ")
                .unwrap(),
            "https://mirror.example.cn/cua/cua-spacesd.tar.gz"
        );
        let hex = "0123456789abcdef".repeat(4);
        for ok in [
            format!("https://mirror.example.cn/bin#sha256={hex}"),
            "http://127.0.0.1:8080/cua-spacesd".into(),
            "http://localhost:9000/cua-spacesd.tar.gz".into(),
            "http://[::1]:9000/cua-spacesd".into(),
            "http://10.0.0.5:8080/cua-spacesd.exe".into(),
        ] {
            assert!(validate_spacesd_download_url(&ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "   ",
            "http://mirror.example.cn/cua-spacesd",
            "http://100.100.100.200/latest/meta-data",
            "http://169.254.169.254/latest/meta-data",
            "ftp://mirror.example.cn/cua-spacesd",
            "https:///no-host.exe",
            "https://mirror.example.cn/bad'quote",
            "https://mirror.example.cn/bad space",
            "https://mirror.example.cn/cua\u{2018}.exe",
            "https://mirror.example.cn/bin#sha256=nothex",
        ] {
            assert!(validate_spacesd_download_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn spacesd_download_url_rejects_userinfo_and_redacts_errors() {
        for bad in [
            "https://user:secret@mirror.example.com/cua-spacesd.tar.gz",
            "http://user:secret@localhost:8080/cua-spacesd",
            "https://127.0.0.1@evil.com/bin",
            "https://user@mirror.example.com/bin",
            "https://:secret@mirror.example.com/bin",
            "https://@mirror.example.com/bin",
            "http://user:secret@mirror.example.com/cua-spacesd.tar.gz",
            "https://user:secret@mirror.example.com/bad space",
            "https://user:secret@[invalid/cua-spacesd",
            "https://user:s3cr3t\\@mirror.example.com/bin",
            "https://s3cr3t\\@mirror.example.com/bin",
            "https://user:8443\\@mirror.example.com/bin",
            "https://user:12345\\@mirror.example.com/bin",
            "https://mirror.example.com\\@s3cr3t@evil.com/bin",
            "https://user:s3cr3t/@mirror.example.com/bin",
            "https://user:s3cr3t/@mirror.example.com/bad space",
            "https://user:s3cr3t/@mirror.example.com/bad space?sig=DeadBeefCafe9988",
            "https://mirror.example.com\\evil.com/bin",
        ] {
            let err = validate_spacesd_download_url(bad).expect_err(bad);
            assert!(
                matches!(err, crate::Error::InvalidArgument(_)),
                "{bad:?} -> {err:?}"
            );
            let msg = err.to_string();
            for leak in [
                "secret",
                "s3cr3t",
                "DeadBeefCafe9988",
                "user:",
                "8443",
                "12345",
                "127.0.0.1@",
                "user@",
            ] {
                assert!(!msg.contains(leak), "{leak:?} leaked for {bad:?}: {msg}");
            }
        }
        for ok in [
            "https://mirror.example.com/@cua/cua-spacesd.tar.gz",
            "https://mirror.example.com/@path/cua-spacesd.tar.gz",
            "http://localhost:8080/@cua/cua-spacesd",
            "https://mirror.example.com/bin?user=ada@example.com",
            "https://mirror.example.com/bin#owner=ada@example.com",
        ] {
            assert!(validate_spacesd_download_url(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn structural_url_redaction_blocks_port_and_delimiter_at_confusion_bypasses() {
        for bad in [
            "https://user:123456#@evil.com/bin",
            "https://user:123456?x=@evil.com/bin",
            "https://user:8080#@evil.com/bin",
            "https://user:8080?x=@evil.com/bin",
            "https://user:s3cr3t?@evil.com/bin",
            "https://user:s3cr3t#@evil.com/bin",
            "https://user:s3cr3t?x=@evil.com/bin",
            "https://user:s3cr3t secret/@evil.com/bin?sig=DeadBeef",
            "https://user:8080 foo/@evil.com/bin",
            "https://user:s3cr3t @mirror.example.com/bin",
            "https://user:8080/@evil.com/bin",
            "https://ada@org:p4ssw0rd/@evil.com/bin",
            "https://ada@org:8080/@evil.com/bin",
            "https://ada@org:secret@mirror.example.com/bin",
            "https://user:s3cr3t\\@mirror.example.com/bin",
            "https://user:8443\\@mirror.example.com/bin",
            "https://mirror.example.com\\@s3cr3t@evil.com/bin",
            "https://example.com:0/bin",
            "https://example.com:/bin",
            "https://example.com:08080/bin",
        ] {
            assert_eq!(redact_url(bad), "<redacted>", "{bad:?}");
            let msg = validate_spacesd_download_url(bad)
                .expect_err(bad)
                .to_string();
            for leak in [
                "user:", "123456", "8080", "8443", "08080", "s3cr3t", "p4ssw0rd", "ada@org",
                "DeadBeef", "secret", "evil.com",
            ] {
                assert!(!msg.contains(leak), "leaked {leak:?} for {bad:?}: {msg}");
            }
        }

        let bad_sha = "https://mirror.example.com/bin#sha256=user:s3cr3t@evil.com";
        let msg = validate_spacesd_download_url(bad_sha)
            .expect_err(bad_sha)
            .to_string();
        assert!(!msg.contains("s3cr3t") && !msg.contains("user:"), "{msg}");

        assert_eq!(
            redact_url("https://mirror.example.com/cua-{version}-{arch}.tar.gz"),
            "https://mirror.example.com/cua-{version}-{arch}.tar.gz"
        );
        assert_eq!(
            redact_url("https://mirror.example.com/@org/cua-spacesd?sig=DeadBeef"),
            "https://mirror.example.com/@org/cua-spacesd"
        );
        assert_eq!(
            redact_url("http://localhost:8080/@cua/cua-spacesd"),
            "http://localhost:8080/@cua/cua-spacesd"
        );
        assert_eq!(
            redact_url("https://cdn.example.com/pkg/@v1/spacesd"),
            "https://cdn.example.com/pkg/@v1/spacesd"
        );
        let sha64 = "0123456789abcdef".repeat(4);
        assert_eq!(
            redact_url(&format!(
                "https://mirror.example.com/bin?user=ada@example.com&sig=AbCd#sha256={sha64}"
            )),
            format!("https://mirror.example.com/bin#sha256={sha64}")
        );
        assert_eq!(
            redact_url(&format!(
                "https://mirror.example.com?user=ada@example.com&sig=AbCd#sha256={sha64}"
            )),
            format!("https://mirror.example.com#sha256={sha64}")
        );
        for ok in [
            "https://mirror.example.com/@org/cua-spacesd",
            "https://cdn.example.com/pkg/@v1/spacesd",
            "http://10.0.0.5:8080/cua-spacesd",
            "http://[::1]:8080/cua-spacesd",
            "http://localhost:9000/cua-spacesd",
            "http://localhost:8080/@cua/cua-spacesd",
            &format!("https://mirror.example.com?user=ada@example.com&sig=AbCd#sha256={sha64}"),
        ] {
            assert!(validate_spacesd_download_url(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn validate_spacesd_url_for_os_rejects_mismatches_and_dir_hashes() {
        let sha64 = "0123456789abcdef".repeat(4);

        let dir_hash = format!("https://mirror.example.com/releases/#sha256={sha64}");
        let err = validate_spacesd_url_for_os(&dir_hash, "windows").unwrap_err();
        assert!(err.contains(".sha256"), "{err}");
        assert!(validate_spacesd_url_for_os(&dir_hash, "linux").is_err());

        assert!(
            validate_spacesd_url_for_os("https://mirror.example.com/releases/", "windows").is_ok()
        );
        assert!(
            validate_spacesd_url_for_os("https://mirror.example.com/releases/", "linux").is_ok()
        );

        for bad in [
            "https://mirror.example.com/cua-spacesd.tar.gz",
            "https://mirror.example.com/cua-spacesd.tgz?sig=1",
            "https://mirror.example.com/cua-spacesd.tar.xz",
            "https://mirror.example.com/cua-spacesd-linux-x86_64",
            "https://mirror.example.com/cua-spacesd-linux-aarch64",
        ] {
            assert!(
                validate_spacesd_url_for_os(bad, "windows").is_err(),
                "{bad}"
            );
            assert!(validate_spacesd_url_for_os(bad, "linux").is_ok(), "{bad}");
        }

        for bad in [
            "https://mirror.example.com/cua-spacesd.exe",
            "https://mirror.example.com/cua-spacesd.msi?sig=1",
        ] {
            assert!(validate_spacesd_url_for_os(bad, "linux").is_err(), "{bad}");
            assert!(
                validate_spacesd_url_for_os(bad, "linux-slim").is_err(),
                "{bad}"
            );
            assert!(validate_spacesd_url_for_os(bad, "windows").is_ok(), "{bad}");
        }

        assert!(
            validate_spacesd_url_for_os(
                &format!("https://mirror.example.com/cua-spacesd.exe#sha256={sha64}"),
                "windows"
            )
            .is_ok()
        );

        let dir_query_hash = format!("https://mirror.example.com/releases/?sig=tok#sha256={sha64}");
        let err = validate_spacesd_url_for_os(&dir_query_hash, "windows").unwrap_err();
        assert!(err.contains(".sha256"), "{err}");
        assert!(!err.contains("sig=tok"), "{err}");
        assert!(validate_spacesd_url_for_os(&dir_query_hash, "linux").is_err());
    }

    #[test]
    fn malformed_scheme_with_later_delimiter_does_not_leak_secrets() {
        let bad = "https:/mirror.example.com/x?sig=SuperSecret&next=https://cdn.example.com";
        assert_eq!(redact_url(bad), "<redacted>");
        let err = validate_spacesd_download_url(bad).expect_err(bad);
        let msg = err.to_string();
        assert!(
            msg.contains("missing URL scheme"),
            "expected missing URL scheme error, got: {msg}"
        );
        assert!(
            !msg.contains("SuperSecret"),
            "secret leaked in error message: {msg}"
        );
        assert_eq!(
            redact_url("https://user:secret@host:badport/path"),
            "<redacted>"
        );
        assert_eq!(
            cua_spaces_contract::inputs::redact_url("https://user:secret@host:badport/path"),
            "<redacted>"
        );
        assert_eq!(cua_spaces_contract::inputs::redact_url(bad), "<redacted>");
    }
}
