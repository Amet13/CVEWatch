//! `unpatched check`.

use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use unpatched_core::{Config, Report};
use unpatched_notify::deliver::deliver_collect;
use unpatched_notify::render::{self, TextOptions};
use unpatched_notify::state::StateStore;
use unpatched_notify::{
    DeliverOptions, Error as NotifyError, FileStore, GitHub, IssuesStore, channels_from_config,
};

use super::out;
use crate::cli::{CheckArgs, Format};
use crate::ctx::{Ctx, load_config, parse_now};
use crate::error::{EXIT_FIX_TODAY, Failure, Res};

/// Evaluate the stack: load the config and the database, run the check.
pub fn evaluate(ctx: &Ctx, config: &Config, now: DateTime<Utc>, allow_stale: bool) -> Res<Report> {
    let db = ctx.open_db()?;
    let info = db.info();
    let age = (now - info.built_at).num_days();
    if age > i64::from(config.thresholds.stale_fail_days) && !allow_stale {
        return Err(Failure::data(
            format!(
                "the database is {age} days old (built {}); the limit is {} days",
                info.built_at.format("%Y-%m-%d"),
                config.thresholds.stale_fail_days
            ),
            "Run `unpatched db update`, check that the daily database build works, or use --allow-stale.",
        ));
    }
    let needs_osv = config.stack.iter().any(|i| i.purl.is_some());
    let http = if needs_osv && !ctx.offline {
        Some(Ctx::http()?)
    } else {
        None
    };
    unpatched_db::run_check(config, &db, http.as_ref(), now).map_err(|e| {
        Failure::data(
            format!("the check failed: {e}"),
            "Try again; if it keeps failing, run `unpatched db sources-health`.",
        )
    })
}

pub fn run(ctx: &Ctx, args: &CheckArgs) -> Res<u8> {
    let now = parse_now(args.now.as_deref())?;
    let config = load_config(&ctx.config)?;
    let report = evaluate(ctx, &config, now, args.allow_stale)?;

    let rendered = match args.format {
        Format::Text => render::text(
            &report,
            &TextOptions {
                verbose: ctx.verbose > 0,
                color: ctx.color && args.output.is_none(),
            },
        ),
        Format::Json => {
            let mut s = render::json(&report);
            s.push('\n');
            s
        }
        Format::Markdown => render::markdown_summary(&report),
        Format::Sarif => {
            let mut s = render::sarif(&report);
            s.push('\n');
            s
        }
    };
    match &args.output {
        Some(path) => {
            write_output(path, &rendered)?;
            if !ctx.quiet {
                eprintln!(
                    "unpatched: {} (report written to {})",
                    summary_line(&report),
                    path.display()
                );
            }
        }
        None => out(&rendered),
    }

    let mut code = 0;
    if args.notify {
        notify(ctx, args, &config, &report, now)?;
    }
    if args.exit_code && report.summary.now > 0 {
        code = EXIT_FIX_TODAY;
    }
    Ok(code)
}

pub fn summary_line(r: &Report) -> String {
    let s = &r.summary;
    if r.findings.is_empty() {
        return "nothing to fix".into();
    }
    format!(
        "{} fix today, {} this week, {} end of life, {} unknown, {} fyi",
        s.now, s.week, s.eol, s.unknown, s.fyi
    )
}

fn write_output(path: &Path, text: &str) -> Res<()> {
    let append = std::env::var_os("GITHUB_STEP_SUMMARY").is_some_and(|p| Path::new(&p) == path);
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true);
    if append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    opts.open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| {
            Failure::usage(
                format!("cannot write {}: {e}", path.display()),
                "Check that the folder exists and you can write to it.",
            )
        })
}

fn notify(
    ctx: &Ctx,
    args: &CheckArgs,
    config: &Config,
    report: &Report,
    now: DateTime<Utc>,
) -> Res<()> {
    let channels = channels_from_config(config).map_err(|e| match e {
        NotifyError::MissingEnv { .. } | NotifyError::Config(_) => Failure::usage(
            e.to_string(),
            "Secrets come from environment variables, never from unpatched.yml.",
        ),
        other => Failure::delivery(
            other.to_string(),
            "Check the channel settings in unpatched.yml.",
        ),
    })?;
    let use_github = args.github || GitHub::in_actions();
    let github = if use_github {
        Some(GitHub::from_env().map_err(|e| {
            Failure::usage(
                e.to_string(),
                "In GitHub Actions set `env: GITHUB_TOKEN: ${{ github.token }}` and give the job `issues: write`.",
            )
        })?)
    } else {
        None
    };
    let store: Box<dyn StateStore> = match &github {
        Some(gh) => Box::new(IssuesStore::new(gh.clone())),
        None => Box::new(FileStore::in_dir(ctx.config_dir())),
    };
    let report_url = match (
        std::env::var("GITHUB_SERVER_URL"),
        std::env::var("GITHUB_REPOSITORY"),
        std::env::var("GITHUB_RUN_ID"),
    ) {
        (Ok(s), Ok(r), Ok(i)) if !s.is_empty() && !r.is_empty() && !i.is_empty() => {
            Some(format!("{s}/{r}/actions/runs/{i}"))
        }
        _ => None,
    };
    let opts = DeliverOptions {
        now,
        dry_run: args.dry_run,
        github,
        force_digest: false,
        report_url,
    };
    let outcome =
        deliver_collect(report, config, store.as_ref(), &channels, &opts).map_err(|e| match e {
            NotifyError::Config(_) => {
                Failure::usage(e.to_string(), "Fix `digest:` in unpatched.yml.")
            }
            other => Failure::delivery(
                other.to_string(),
                "Check the saved state (.unpatched/state.json or the status issue).",
            ),
        })?;

    if !ctx.quiet {
        let prefix = if args.dry_run { "dry run: " } else { "" };
        if let Some(s) = &outcome.issues {
            eprintln!(
                "{prefix}issues: {} created, {} updated, {} closed, {} reopened",
                s.created.len(),
                s.updated.len(),
                s.closed.len(),
                s.reopened.len()
            );
        }
        if let Some(n) = outcome.status_issue.filter(|n| *n > 0) {
            eprintln!("{prefix}status issue: #{n}");
        }
        for m in &outcome.sent {
            eprintln!(
                "{prefix}{}: {} ({} item(s))",
                m.channel,
                m.event.as_str(),
                m.items
            );
        }
        for p in &outcome.planned {
            eprintln!("dry run: would {p}");
        }
    }
    if outcome.errors.is_empty() {
        Ok(())
    } else {
        Err(Failure::delivery(
            outcome.errors.join("\n"),
            "The other channels were still delivered. Fix the failing channel and run again.",
        ))
    }
}
