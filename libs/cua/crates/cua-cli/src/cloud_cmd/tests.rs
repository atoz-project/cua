use super::*;
use clap::Parser;

#[derive(Parser)]
struct T {
    #[command(subcommand)]
    cmd: CloudCmd,
}

fn parse(a: &[&str]) -> CloudCmd {
    T::try_parse_from(std::iter::once("cloud").chain(a.iter().copied()))
        .unwrap()
        .cmd
}

fn parse_err(a: &[&str]) -> bool {
    T::try_parse_from(std::iter::once("cloud").chain(a.iter().copied())).is_err()
}

#[test]
fn an_audit_line_names_who_did_what() {
    let e = cua_sdk::CloudAuditEntry {
        ts: "2026-10-21T09:00:00Z".into(),
        action: "resource_deleted".into(),
        provider: "aws".into(),
        kind: "instance".into(),
        id: "i-1".into(),
        space: "research".into(),
        actor: "auto-sweep".into(),
        outcome: "ok".into(),
        detail: "expired".into(),
        source: String::new(),
    };
    let l = audit_line(&e);
    assert!(
        l.ends_with("instance i-1 · research · auto-sweep · ok · expired"),
        "{l}"
    );
    assert_eq!(audit_json(&e)["actor"], "auto-sweep");
}

#[test]
fn approve_parses_and_hint_lines_are_short_and_plain() {
    assert!(matches!(
        parse(&["approve", "aws"]),
        CloudCmd::Approve { provider, deny: false } if provider == "aws"
    ));
    assert!(matches!(
        parse(&["approve", "aws", "--deny"]),
        CloudCmd::Approve { deny: true, .. }
    ));
    assert!(parse_err(&["approve"]));
    let p = cua_sdk::CloudProvider {
        name: "aws".into(),
        title: "AWS".into(),
        connected: true,
        auth: "cli".into(),
        suggest_auth: "oidc".into(),
        ..Default::default()
    };
    assert_eq!(
        hint_lines(&p),
        vec!["  Switch to OIDC (no stored key): cua cloud connect aws --oidc".to_string()]
    );
    let p = cua_sdk::CloudProvider {
        name: "aws".into(),
        title: "AWS".into(),
        connected: true,
        auth: "oidc".into(),
        approval: "limits".into(),
        approval_agent: "researcher".into(),
        pending_budget_usd_month: Some(500.0),
        can_approve: true,
        ..Default::default()
    };
    let l = hint_lines(&p);
    assert_eq!(
        l[0],
        "  Agent researcher asks for a budget of $500 a month."
    );
    assert!(l[1].contains("cua cloud approve aws --deny"), "{l:?}");
    // An agent's shell gets no approve line (it could not run it).
    let agent = cua_sdk::CloudProvider {
        can_approve: false,
        ..p
    };
    assert!(hint_lines(&agent).is_empty());
    for line in hint_lines(&cua_sdk::CloudProvider {
        issue: "AWS was disconnected from your Cua account.".into(),
        ..Default::default()
    }) {
        assert!(!line.contains('\u{b7}'), "no dot chains: {line}");
    }
    let j = provider_json(&agent);
    for k in [
        "approval_agent",
        "pending_budget_usd_month",
        "pending_max_size",
        "can_approve",
        "suggest_auth",
        "issue",
    ] {
        assert!(j.get(k).is_some(), "{k} missing from --json");
    }
}

#[test]
fn a_connected_cloud_prints_its_place_once() {
    let p = cua_sdk::CloudProvider {
        name: "gcp".into(),
        title: "Google Cloud".into(),
        connected: true,
        label: "Google Cloud \u{b7} us-central1".into(),
        account: "cua-byoc-test".into(),
        ..Default::default()
    };
    let l = provider_line(&p);
    assert_eq!(l.matches("Google Cloud").count(), 1, "{l}");
    assert!(l.contains("connected · us-central1 · cua-byoc-test"), "{l}");
}

#[test]
fn connect_takes_the_agent_flags_and_never_prompts() {
    match parse(&[
        "connect",
        "aws",
        "--oidc",
        "--region",
        "us-west-2",
        "--budget",
        "200",
        "--max-size",
        "4x16",
        "--account-id",
        "123456789012",
        "--check",
    ]) {
        CloudCmd::Connect {
            target,
            oidc,
            budget,
            max_size,
            account_id,
            check,
            role_arn,
            ..
        } => {
            assert_eq!(target.provider, "aws");
            assert!(oidc && check);
            assert_eq!(budget, Some(200.0));
            assert_eq!(max_size.as_deref(), Some("4x16"));
            assert_eq!(account_id.as_deref(), Some("123456789012"));
            assert_eq!(role_arn, None);
        }
        other => panic!("{other:?}"),
    }
    assert!(parse_err(&["connect", "aws", "--budget", "lots"]));
    match parse(&[
        "connect",
        "gcp",
        "--oidc",
        "--project",
        "my-project",
        "--project-number",
        "123456789012",
        "--service-account",
        "cua@my-project.iam.gserviceaccount.com",
        "--budget",
        "200",
        "--check",
    ]) {
        CloudCmd::Connect {
            target,
            project_number,
            service_account,
            ..
        } => {
            assert_eq!(target.project.as_deref(), Some("my-project"));
            assert_eq!(project_number.as_deref(), Some("123456789012"));
            assert_eq!(
                service_account.as_deref(),
                Some("cua@my-project.iam.gserviceaccount.com")
            );
        }
        other => panic!("{other:?}"),
    }
    match parse(&[
        "connect",
        "azure",
        "--region",
        "westus2",
        "--budget",
        "200",
        "--subscription",
        "s",
        "--tenant",
        "t",
        "--client-id",
        "c",
        "--resource-group",
        "rg",
        "--check",
    ]) {
        CloudCmd::Connect {
            target,
            oidc,
            subscription_id,
            tenant_id,
            client_id,
            resource_group,
            check,
            ..
        } => {
            assert_eq!(target.provider, "azure");
            // Azure needs no --oidc: it has no other way.
            assert!(!oidc && check);
            assert_eq!(
                (
                    subscription_id.as_deref(),
                    tenant_id.as_deref(),
                    client_id.as_deref(),
                    resource_group.as_deref()
                ),
                (Some("s"), Some("t"), Some("c"), Some("rg"))
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse(&["trust", "gcp"]),
        CloudCmd::Trust { cloud } if cloud == "gcp"
    ));
    // The help an agent follows names every status, the exit codes and
    // the steps.
    for word in [
        "needs-trust",
        "checking",
        "waiting-for-approval",
        "connected",
        "failed",
        "0 connected, 10",
        "11 it waits on a",
        "--account-id <ID> --check",
        "cua cloud status aws",
        "--project-number <N> --check",
        "cua cloud status gcp",
        "--subscription --tenant --client-id --check",
        "cua cloud status azure",
        "https://cua.ai/docs/spaces/guides/connect-a-cloud",
    ] {
        assert!(CONNECT_HELP.contains(word), "{word}");
    }
}

#[test]
fn hetzner_and_modal_seal_their_token_unless_told_not_to() {
    match parse(&[
        "connect",
        "hetzner",
        "--token-stdin",
        "--region",
        "fsn1",
        "--budget",
        "50",
        "--max-size",
        "4x8",
    ]) {
        CloudCmd::Connect {
            target,
            sealed,
            no_sealed,
            oidc,
            budget,
            ..
        } => {
            assert!(target.token_stdin);
            // Neither: the default (sealed with pool keys and a budget).
            assert!(!sealed && !no_sealed && !oidc);
            assert_eq!(budget, Some(50.0));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse(&["connect", "hetzner", "--sealed", "--budget", "50"]),
        CloudCmd::Connect { sealed: true, .. }
    ));
    assert!(matches!(
        parse(&["connect", "hetzner", "--no-sealed", "--token-stdin"]),
        CloudCmd::Connect {
            no_sealed: true,
            ..
        }
    ));
    assert!(parse_err(&[
        "connect",
        "hetzner",
        "--sealed",
        "--no-sealed"
    ]));
    assert!(parse_err(&["connect", "aws", "--oidc", "--sealed"]));
    for word in [
        "--token-stdin --region fsn1 --budget 50",
        "--no-sealed",
        "<token id>:<token secret>",
        "can open it",
        "--sealed without a token",
    ] {
        assert!(CONNECT_HELP.contains(word), "{word}");
    }
    // Status says who can open it.
    let p = cua_sdk::CloudProvider {
        name: "hetzner".into(),
        title: "Hetzner".into(),
        connected: true,
        auth: "sealed".into(),
        holders: vec!["Dillon's MacBook".into(), "studio".into()],
        ..Default::default()
    };
    assert_eq!(
        limits_line(&p).unwrap(),
        "  Token sealed; can open it: Dillon's MacBook, studio."
    );
    assert_eq!(provider_json(&p)["holders"][1], "studio");
}

fn outcome(status: &str, next: Option<cua_sdk::CloudNext>) -> cua_sdk::CloudConnected {
    cua_sdk::CloudConnected {
        provider: cua_sdk::CloudProvider {
            name: "aws".into(),
            title: "AWS".into(),
            status: status.into(),
            region: "us-west-2".into(),
            auth: "oidc".into(),
            budget_usd_month: Some(200.0),
            max_size: "4x16".into(),
            connected: status == "connected",
            ..Default::default()
        },
        next,
        verify: "cua cloud status aws".into(),
        ..Default::default()
    }
}

#[test]
fn every_connect_ends_with_status_next_and_verify() {
    let run = |r: &str| cua_sdk::CloudNext {
        run: Some(r.into()),
        why: "w".into(),
        ..Default::default()
    };
    let open = cua_sdk::CloudNext {
        open: Some("https://us-west-2.console.aws.amazon.com/cloudshell/home".into()),
        paste: Some("curl … && aws cloudformation deploy …".into()),
        why: "AWS does not trust Cua yet.".into(),
        ..Default::default()
    };
    assert_eq!(connect_exit_code(&outcome("connected", None)), 0);
    assert_eq!(connect_exit_code(&outcome("checking", Some(run("x")))), 10);
    assert_eq!(connect_exit_code(&outcome("failed", Some(run("x")))), 10);
    assert_eq!(
        connect_exit_code(&outcome("needs-trust", Some(open.clone()))),
        11
    );
    assert_eq!(
        connect_exit_code(&outcome(
            "waiting-for-approval",
            Some(cua_sdk::CloudNext {
                why: "a person approves".into(),
                ..Default::default()
            })
        )),
        11
    );
    assert_eq!(connect_exit_code(&outcome("failed", None)), 1);
    assert_eq!(
        plain_error("invalid argument: invalid argument: max size"),
        "invalid argument: max size"
    );
    assert_eq!(plain_error("cloud: aws: x"), "cloud: aws: x");

    let v = connect_json(&outcome("needs-trust", Some(open.clone())));
    assert_eq!(v["status"], "needs-trust");
    assert_eq!(v["verify"], "cua cloud status aws");
    assert!(v["next"]["open"].as_str().unwrap().contains("cloudshell"));
    assert!(v["next"].get("run").is_none());
    assert_eq!(v["checks"], serde_json::json!([]));
    assert_eq!(v["provider"]["budget_usd_month"], 200.0);
    assert!(connect_json(&outcome("connected", None))["next"].is_null());

    let lines = connect_lines(&outcome("needs-trust", Some(open)));
    assert_eq!(lines[0], "AWS: needs trust");
    assert!(
        lines.contains(&"Budget: $200 a month".to_string()),
        "{lines:?}"
    );
    assert!(lines.contains(&"Machines up to 4 vCPU and 16 GB".to_string()));
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("Next, for a person: open https://"))
    );
    assert!(lines.iter().any(|l| l.starts_with("Paste there: ")));
    assert_eq!(lines.last().unwrap(), "Verify: cua cloud status aws");
    // Short plain lines: no "a · b · c" chains.
    assert!(lines.iter().all(|l| !l.contains('\u{b7}')), "{lines:?}");
    let done = connect_lines(&outcome("connected", None));
    assert_eq!(done[0], "AWS: connected");
    assert!(done.contains(&"Create a Space there: cua spaces create --on aws".to_string()));
}

#[test]
fn the_commands_parse() {
    match parse(&["connect", "aws", "--region", "us-west-2", "--default"]) {
        CloudCmd::Connect {
            target,
            make_default,
            ttl_hours,
            ..
        } => {
            assert_eq!(target.target().provider, "aws");
            assert_eq!(target.region.as_deref(), Some("us-west-2"));
            assert!(make_default);
            assert_eq!(ttl_hours, None);
        }
        other => panic!("{other:?}"),
    }
    match parse(&["sweep", "gcp"]) {
        CloudCmd::Sweep {
            provider,
            delete,
            all,
        } => assert_eq!(
            (provider.as_deref(), delete, all),
            (Some("gcp"), false, false)
        ),
        other => panic!("{other:?}"),
    }
    match parse(&[
        "add",
        "aws",
        "--count",
        "2",
        "--type",
        "g6.xlarge",
        "--ttl-hours",
        "6",
        "--tag",
        "team=ml",
    ]) {
        CloudCmd::Add {
            cloud: AddCloud::Aws(a),
        } => {
            assert_eq!((a.count, a.instance_type.as_str()), (2, "g6.xlarge"));
            assert_eq!(
                (a.ttl_hours, a.tags.as_slice()),
                (Some(6), &["team=ml".to_string()][..])
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse(&["add", "aws", "--down", "--name", "aws-3"]),
        CloudCmd::Add { cloud: AddCloud::Aws(a) } if a.down && a.name.as_deref() == Some("aws-3")
    ));
    assert!(parse_err(&["add", "aws", "--list", "--down"]));
    assert!(matches!(
        parse(&["disconnect", "AWS"]),
        CloudCmd::Disconnect { provider, delete: false } if provider == "AWS"
    ));
    assert!(matches!(
        parse(&["disconnect", "aws", "--delete"]),
        CloudCmd::Disconnect { delete: true, .. }
    ));
    assert!(matches!(
        parse(&["audit"]),
        CloudCmd::Audit {
            limit: 50,
            cloud: None
        }
    ));
    assert!(matches!(
        parse(&["audit", "--limit", "7", "--cloud", "aws"]),
        CloudCmd::Audit { limit: 7, cloud: Some(c) } if c == "aws"
    ));
    assert!(matches!(
        parse(&["cost"]),
        CloudCmd::Cost { by, format, since: None, cloud: None } if by == "space" && format == "table"
    ));
    assert!(matches!(
        parse(&["cost", "--by", "day", "--since", "2026-10-01", "--format", "csv", "--cloud", "aws"]),
        CloudCmd::Cost { by, format, since: Some(d), cloud: Some(c) }
            if by == "day" && format == "csv" && d == "2026-10-01" && c == "aws"
    ));
    assert!(parse_err(&["cost", "--by", "week"]));
    assert!(parse_err(&["cost", "--format", "xml"]));
    assert!(parse_err(&["audit", "--limit", "many"]));
    assert!(matches!(
        parse(&["ls"]),
        CloudCmd::Status { provider: None }
    ));
    match parse(&["connect", "hetzner", "--token-stdin", "--region", "nbg1"]) {
        CloudCmd::Connect { target, .. } => {
            assert_eq!(target.provider, "hetzner");
            assert!(target.token_stdin);
            assert_eq!(target.region.as_deref(), Some("nbg1"));
        }
        other => panic!("{other:?}"),
    }
    // Without the flag the token is never read from stdin.
    match parse(&["connect", "hetzner"]) {
        CloudCmd::Connect { target, .. } => {
            assert!(!target.token_stdin);
            assert_eq!(target.target().token, None);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse(&["test", "MODAL", "--environment", "e"]),
        CloudCmd::Test { target } if target.target().provider == "modal"
    ));
}

#[test]
fn aliyun_ecs_commands_and_help_parse() {
    match parse(&[
        "test",
        "ALIYUN-ECS",
        "--profile",
        "webhook_manager",
        "--region",
        "cn-shanghai",
    ]) {
        CloudCmd::Test { target } => {
            let t = target.target();
            assert_eq!(t.provider, "aliyun-ecs");
            assert_eq!(t.profile.as_deref(), Some("webhook_manager"));
            assert_eq!(t.region.as_deref(), Some("cn-shanghai"));
        }
        other => panic!("{other:?}"),
    }
    match parse(&[
        "connect",
        "aliyun-ecs",
        "--token-stdin",
        "--region",
        "cn-hangzhou",
        "--budget",
        "50",
        "--max-size",
        "4x16",
        "--ttl-hours",
        "4",
        "--default",
    ]) {
        CloudCmd::Connect {
            target,
            make_default,
            ttl_hours,
            budget,
            max_size,
            ..
        } => {
            assert_eq!(target.provider, "aliyun-ecs");
            assert!(target.token_stdin);
            assert_eq!(target.region.as_deref(), Some("cn-hangzhou"));
            assert!(make_default);
            assert_eq!(ttl_hours, Some(4));
            assert_eq!(budget, Some(50.0));
            assert_eq!(max_size.as_deref(), Some("4x16"));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        parse(&["status", "aliyun-ecs"]),
        CloudCmd::Status { provider: Some(p) } if p == "aliyun-ecs"
    ));
    assert!(matches!(
        parse(&["disconnect", "aliyun-ecs"]),
        CloudCmd::Disconnect { provider, delete: false } if provider == "aliyun-ecs"
    ));
    for needle in [
        "aliyun-ecs",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "~/.aliyun/config.json",
        "cn-hangzhou",
    ] {
        assert!(CONNECT_HELP.contains(needle), "{needle}");
    }
}

#[test]
fn token_stdin_preserves_empty_or_whitespace_input() {
    let empty = TargetArgs {
        provider: "aliyun-ecs".into(),
        token_stdin: true,
        ..Default::default()
    };
    assert_eq!(
        empty.target_with_stdin(String::new).token.as_deref(),
        Some("")
    );
    assert_eq!(
        empty
            .target_with_stdin(|| "  \n\t ".into())
            .token
            .as_deref(),
        Some("")
    );
    assert_eq!(
        empty
            .target_with_stdin(|| " ak:sk \n".into())
            .token
            .as_deref(),
        Some("ak:sk")
    );
    let no_stdin = TargetArgs {
        provider: "aliyun-ecs".into(),
        token_stdin: false,
        ..Default::default()
    };
    assert_eq!(no_stdin.target_with_stdin(|| "ignored".into()).token, None);
}

#[test]
fn cost_prints_plain_columns_and_a_stable_csv() {
    let r = cua_sdk::CloudCostReport {
        by: "space".into(),
        since: "2026-10-01".into(),
        until: "2026-10-24T12:00:00Z".into(),
        rows: vec![
            cua_sdk::CloudCostRow {
                key: "research".into(),
                usd: 4.5,
                hours: 9.0,
                machines: 2,
            },
            cua_sdk::CloudCostRow {
                key: "a,b".into(),
                usd: 1.0,
                hours: 1.0,
                machines: 1,
            },
        ],
        total_usd: 5.5,
    };
    // Scripts read this header: only ever add columns at the end.
    assert_eq!(COST_CSV_HEADER, "key,usd,hours,machines");
    assert_eq!(
        cost_csv(&r.rows),
        "key,usd,hours,machines\nresearch,4.50,9.00,2\n\"a,b\",1.00,1.00,1\n"
    );
    let t = cost_table(&r);
    assert!(t[0].starts_with("Space"), "{t:?}");
    assert!(t[1].contains("$4.50"), "{t:?}");
    assert_eq!(
        t[3],
        "Total $5.50 since 2026-10-01 (estimated from list prices)."
    );
    assert!(
        t.iter().all(|l| !l.contains('\u{b7}')),
        "no dot chains: {t:?}"
    );
    let empty = cua_sdk::CloudCostReport {
        since: "2026-10-01".into(),
        ..Default::default()
    };
    assert_eq!(cost_table(&empty), vec!["Nothing ran since 2026-10-01."]);
    assert_eq!(cost_json(&r)["rows"][0]["key"], "research");
}

#[test]
fn relay_flags_parse_conflict_preserve_empty_stdin_and_redact_output() {
    match parse(&[
        "connect",
        "hetzner",
        "--relay-url",
        "https://relay.example.com/",
        "--relay-mode",
        "static",
        "--relay-token-stdin",
        "--spacesd-download-url",
        "https://mirror.example.com/cua-spacesd.exe",
    ]) {
        CloudCmd::Connect { target, .. } => {
            assert_eq!(
                target.relay_url.as_deref(),
                Some("https://relay.example.com/")
            );
            assert_eq!(target.relay_mode.as_deref(), Some("static"));
            assert!(target.relay_token_stdin);
            assert_eq!(
                target.spacesd_download_url.as_deref(),
                Some("https://mirror.example.com/cua-spacesd.exe")
            );
            let wire = target.target_with_stdin(|| "  static-tok \n".into());
            assert_eq!(wire.relay_token.as_deref(), Some("static-tok"));
            assert_eq!(wire.relay_mode.as_deref(), Some("static"));
            assert_eq!(
                wire.spacesd_download_url.as_deref(),
                Some("https://mirror.example.com/cua-spacesd.exe")
            );
            assert!(!format!("{wire:?}").contains("static-tok"));
        }
        other => panic!("{other:?}"),
    }

    let empty = TargetArgs {
        provider: "hetzner".into(),
        relay_token_stdin: true,
        ..Default::default()
    };
    assert_eq!(
        empty
            .target_with_stdin(|| " \t\n ".into())
            .relay_token
            .as_deref(),
        Some("")
    );

    match parse(&[
        "connect",
        "aliyun-ecs",
        "--token-stdin",
        "--relay-url",
        "https://relay.example.com",
        "--relay-mode",
        "static",
        "--relay-token-stdin",
    ]) {
        CloudCmd::Connect { target, .. } => {
            assert!(target.token_stdin);
            assert!(target.relay_token_stdin);
            let wire = target.target_with_stdin(|| "  LTAI_AK:secret123 \n  static-tok \n".into());
            assert_eq!(wire.token.as_deref(), Some("LTAI_AK:secret123"));
            assert_eq!(wire.relay_token.as_deref(), Some("static-tok"));
            assert!(!format!("{wire:?}").contains("secret123"));
            assert!(!format!("{wire:?}").contains("static-tok"));

            let empty_line2 = target.target_with_stdin(|| "LTAI_AK:secret123\n   \n".into());
            assert_eq!(empty_line2.token.as_deref(), Some("LTAI_AK:secret123"));
            assert_eq!(empty_line2.relay_token.as_deref(), Some(""));

            let missing_line2 = target.target_with_stdin(|| "LTAI_AK:secret123\n".into());
            assert_eq!(missing_line2.token.as_deref(), Some("LTAI_AK:secret123"));
            assert_eq!(missing_line2.relay_token.as_deref(), Some(""));

            let empty_line1 = target.target_with_stdin(|| "  \nstatic-tok\n".into());
            assert_eq!(empty_line1.token.as_deref(), Some(""));
            assert_eq!(empty_line1.relay_token.as_deref(), Some("static-tok"));
        }
        other => panic!("{other:?}"),
    }

    let p = cua_sdk::CloudProvider {
        name: "hetzner".into(),
        title: "Hetzner Cloud".into(),
        connected: true,
        status: "connected".into(),
        auth: "token".into(),
        relay_url: Some("https://relay.example.com".into()),
        relay_mode: Some("static".into()),
        ..Default::default()
    };
    let lines = connect_lines(&cua_sdk::CloudConnected {
        provider: p.clone(),
        verify: "cua cloud status hetzner".into(),
        ..Default::default()
    });
    assert!(
        lines
            .iter()
            .any(|l| l == "Relay: https://relay.example.com (static)"),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("https://relay.example.com"))
    );
    let lim = limits_line(&p).unwrap();
    assert!(lim.contains("https://relay.example.com"), "{lim}");
    assert!(lim.contains("Static Relay Mode"), "{lim}");
    let j = provider_json(&p);
    assert_eq!(j["relay_mode"], "static");
    assert_eq!(j["relay_url"], "https://relay.example.com");
}

#[test]
fn aliyun_ecs_existing_vpc_flags_parse_and_render() {
    match parse(&[
        "test",
        "aliyun-ecs",
        "--vpc-id",
        "vpc-user-1",
        "--vswitch-id",
        "vsw-user-1",
        "--no-public-ip",
    ]) {
        CloudCmd::Test { target } => {
            let wire = target.target_with_stdin(String::new);
            assert_eq!(wire.vpc_id.as_deref(), Some("vpc-user-1"));
            assert_eq!(wire.vswitch_id.as_deref(), Some("vsw-user-1"));
            assert!(wire.no_public_ip);
        }
        other => panic!("{other:?}"),
    }
    match parse(&[
        "connect",
        "aliyun-ecs",
        "--vpc-id",
        "vpc-user-1",
        "--vswitch-id",
        "vsw-user-1",
        "--no-public-ip",
    ]) {
        CloudCmd::Connect { target, .. } => {
            let wire = target.target_with_stdin(String::new);
            assert_eq!(wire.vpc_id.as_deref(), Some("vpc-user-1"));
            assert_eq!(wire.vswitch_id.as_deref(), Some("vsw-user-1"));
            assert!(wire.no_public_ip);
        }
        other => panic!("{other:?}"),
    }

    let p = cua_sdk::CloudProvider {
        name: "aliyun-ecs".into(),
        title: "Alibaba Cloud ECS".into(),
        connected: true,
        status: "connected".into(),
        vpc_id: Some("vpc-user-1".into()),
        vswitch_id: Some("vsw-user-1".into()),
        no_public_ip: true,
        ..Default::default()
    };
    let lim = limits_line(&p).unwrap();
    assert!(
        lim.contains("vpc-user-1") && lim.contains("vsw-user-1"),
        "{lim}"
    );
    assert!(lim.contains("--no-public-ip"), "{lim}");

    let lines = connect_lines(&cua_sdk::CloudConnected {
        provider: p.clone(),
        verify: "cua cloud status aliyun-ecs".into(),
        ..Default::default()
    });
    assert!(
        lines
            .iter()
            .any(|l| l.contains("vpc-user-1") && l.contains("vsw-user-1")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("--no-public-ip")),
        "{lines:?}"
    );

    let j = provider_json(&p);
    assert_eq!(j["vpc_id"], "vpc-user-1");
    assert_eq!(j["vswitch_id"], "vsw-user-1");
    assert_eq!(j["no_public_ip"], true);
}

#[test]
fn cloud_connect_and_test_parse_image_id_and_instance_type_defaults() {
    match parse(&[
        "connect",
        "aliyun-ecs",
        "--region",
        "cn-hangzhou",
        "--windows-image-id",
        "m-win11",
        "--linux-image-id",
        "m-ubuntu",
        "--instance-type",
        "ecs.c7.2xlarge",
        "--max-size",
        "8x32x120",
    ]) {
        CloudCmd::Connect {
            target, max_size, ..
        } => {
            assert_eq!(max_size.as_deref(), Some("8x32x120"));
            let wire = target.target_with_stdin(String::new);
            assert_eq!(wire.windows_image_id.as_deref(), Some("m-win11"));
            assert_eq!(wire.linux_image_id.as_deref(), Some("m-ubuntu"));
            assert_eq!(wire.instance_type.as_deref(), Some("ecs.c7.2xlarge"));
        }
        other => panic!("{other:?}"),
    }

    match parse(&[
        "test",
        "aliyun-ecs",
        "--windows-image-id",
        "m-win10",
        "--linux-image-id",
        "m-lin",
        "--instance-type",
        "ecs.g7.large",
    ]) {
        CloudCmd::Test { target } => {
            let wire = target.target_with_stdin(String::new);
            assert_eq!(wire.windows_image_id.as_deref(), Some("m-win10"));
            assert_eq!(wire.linux_image_id.as_deref(), Some("m-lin"));
            assert_eq!(wire.instance_type.as_deref(), Some("ecs.g7.large"));
        }
        other => panic!("{other:?}"),
    }

    assert_eq!(size_words("4x16"), "4 vCPU and 16 GB");
    assert_eq!(size_words("8x32x120"), "8 vCPU, 32 GB, and 120 GB disk");

    let p = cua_sdk::CloudProvider {
        name: "aliyun-ecs".into(),
        title: "Alibaba Cloud ECS".into(),
        connected: true,
        status: "connected".into(),
        windows_image_id: Some("m-win11".into()),
        linux_image_id: Some("m-ubuntu".into()),
        instance_type: Some("ecs.c7.2xlarge".into()),
        ..Default::default()
    };
    let lim = limits_line(&p).unwrap();
    assert!(lim.contains("Windows Cloud Image ID: m-win11"), "{lim}");
    assert!(lim.contains("Linux Cloud Image ID: m-ubuntu"), "{lim}");
    assert!(
        lim.contains("Default instance type: ecs.c7.2xlarge"),
        "{lim}"
    );
    let j = provider_json(&p);
    assert_eq!(j["windows_image_id"], "m-win11");
    assert_eq!(j["linux_image_id"], "m-ubuntu");
    assert_eq!(j["instance_type"], "ecs.c7.2xlarge");
}

#[test]
fn spacesd_download_url_flag_parses_for_connect_and_test() {
    let url = "https://mirror.example.cn/cua/cua-spacesd-linux-x86_64.tar.gz";
    match parse(&["connect", "aliyun-ecs", "--spacesd-download-url", url]) {
        CloudCmd::Connect { target, .. } => {
            assert_eq!(target.provider, "aliyun-ecs");
            assert_eq!(target.spacesd_download_url.as_deref(), Some(url));
            let wire = target.target_with_stdin(String::new);
            assert_eq!(wire.spacesd_download_url.as_deref(), Some(url));
        }
        other => panic!("{other:?}"),
    }
    match parse(&["test", "aliyun-ecs", "--spacesd-download-url", url]) {
        CloudCmd::Test { target } => {
            assert_eq!(target.provider, "aliyun-ecs");
            assert_eq!(target.spacesd_download_url.as_deref(), Some(url));
        }
        other => panic!("{other:?}"),
    }

    let p = cua_sdk::CloudProvider {
        name: "aliyun-ecs".into(),
        title: "Alibaba Cloud ECS".into(),
        connected: true,
        status: "connected".into(),
        spacesd_download_url: Some(url.into()),
        ..Default::default()
    };
    assert_eq!(provider_json(&p)["spacesd_download_url"], url);
}
