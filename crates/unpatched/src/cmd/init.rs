//! `unpatched init`.

use std::fmt::Write as _;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use super::out;
use crate::cli::InitArgs;
use crate::ctx::{Ctx, suggest};
use crate::error::{Failure, Res};

const CONFIG_TEMPLATE: &str = include_str!("../../templates/unpatched.yml");
const WORKFLOW_TEMPLATE: &str = include_str!("../../templates/workflow.yml");

pub fn run(ctx: &Ctx, args: &InitArgs) -> Res<u8> {
    let config_path = &ctx.config;
    let workflow_path = workflow_path(config_path);
    if !args.force {
        for p in std::iter::once(config_path).chain(args.github.then_some(&workflow_path)) {
            if p.exists() {
                return Err(Failure::usage(
                    format!("{} already exists", p.display()),
                    "Use --force to overwrite it, or --config <file> to write somewhere else.",
                ));
            }
        }
    }

    let stdin = std::io::stdin();
    let text = if stdin.is_terminal() {
        let mut input = stdin.lock();
        let mut output = std::io::stderr();
        interactive(&mut input, &mut output).map_err(|e| {
            Failure::usage(format!("cannot read your answers: {e}"), "Run `unpatched init` in a terminal, or edit the template it writes when input is not a terminal.")
        })?
    } else {
        CONFIG_TEMPLATE.to_owned()
    };
    write(config_path, &text)?;
    out(&format!("Wrote {}\n", config_path.display()));
    if args.github {
        write(&workflow_path, WORKFLOW_TEMPLATE)?;
        out(&format!("Wrote {}\n", workflow_path.display()));
    }
    out(&next_steps(args.github));
    Ok(0)
}

fn workflow_path(config: &Path) -> PathBuf {
    let dir = match config.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    dir.join(".github").join("workflows").join("unpatched.yml")
}

fn write(path: &Path, text: &str) -> Res<()> {
    let fail = |e: std::io::Error| {
        Failure::usage(
            format!("cannot write {}: {e}", path.display()),
            "Check that you can write there.",
        )
    };
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    std::fs::write(path, text).map_err(fail)
}

fn next_steps(github: bool) -> String {
    let mut s = String::from("\nNext steps:\n");
    s.push_str("  1. Edit unpatched.yml: list what you really run, with exact versions.\n");
    s.push_str("  2. Run `unpatched check` to see the result.\n");
    if github {
        s.push_str(
            "  3. Keep this repository PRIVATE: unpatched.yml lists your software and versions.\n",
        );
        s.push_str("  4. Commit and push both files. The workflow runs every day at 06:17 UTC; start it once from the Actions tab (workflow_dispatch).\n");
        s.push_str("  5. For Telegram, Slack, Discord, ntfy or a webhook, add the secrets named in unpatched.yml under Settings > Secrets and variables > Actions, and uncomment the `env:` lines in the workflow.\n");
    } else {
        s.push_str("  3. Run `unpatched init --github` to add the daily GitHub workflow.\n");
    }
    s
}

struct Item {
    product: Option<String>,
    purl: Option<String>,
    version: Option<String>,
    internet: bool,
    name: Option<String>,
}

fn ask(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    prompt: &str,
) -> std::io::Result<Option<String>> {
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_owned()))
}

/// Ask for the stack one product at a time; returns the file text.
pub fn interactive(input: &mut dyn BufRead, output: &mut dyn Write) -> std::io::Result<String> {
    writeln!(
        output,
        "List the software you run. Type a name to search the catalog, a catalog id, or a package URL (pkg:...). An empty line finishes.\n"
    )?;
    let mut items: Vec<Item> = Vec::new();
    while let Some(answer) = ask(input, output, "Product: ")? {
        if answer.is_empty() {
            break;
        }
        if answer.starts_with("pkg:") {
            if !answer.contains('@') {
                writeln!(
                    output,
                    "A package URL needs a version: pkg:type/name@version"
                )?;
                continue;
            }
            items.push(Item {
                product: None,
                purl: Some(answer),
                version: None,
                internet: false,
                name: None,
            });
            continue;
        }
        let entry = if let Some(e) = unpatched_catalog::get(&answer) {
            e
        } else {
            let found = suggest(&answer);
            if found.is_empty() {
                writeln!(output, "No product matches {answer:?}. Try another name.")?;
                continue;
            }
            for (i, e) in found.iter().enumerate() {
                writeln!(output, "  {}. {} ({}, {})", i + 1, e.id, e.name, e.vendor)?;
            }
            let Some(pick) = ask(input, output, "Number (empty to search again): ")? else {
                break;
            };
            match pick
                .parse::<usize>()
                .ok()
                .and_then(|n| found.get(n.wrapping_sub(1)).copied())
            {
                Some(e) => e,
                None => continue,
            }
        };
        let version = loop {
            let Some(v) = ask(input, output, &format!("Version of {}: ", entry.name))? else {
                break None;
            };
            if !v.is_empty() {
                break Some(v);
            }
        };
        let Some(version) = version else { break };
        if let Err(e) = entry.versioning.validate(&version) {
            writeln!(
                output,
                "Note: {e}. unpatched will report this item as unknown until the version is fixed."
            )?;
        }
        let internet = ask(input, output, "Reachable from the internet? [y/N]: ")?
            .is_some_and(|a| matches!(a.to_ascii_lowercase().as_str(), "y" | "yes"));
        let name = ask(input, output, "Your label for it (optional): ")?.filter(|n| !n.is_empty());
        items.push(Item {
            product: Some(entry.id.clone()),
            purl: None,
            version: Some(version),
            internet,
            name,
        });
    }
    Ok(render(&items))
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn render(items: &[Item]) -> String {
    let mut s = String::from(
        "# unpatched.yml: what you run, and where to tell you.\n# Keep this file in a PRIVATE repository: it lists your software and versions.\n\nversion: 1\n\n",
    );
    if items.is_empty() {
        s.push_str("# Add what you run, for example:\n#   - product: fortios\n#     version: 7.2.5\n#     exposure: internet\nstack: []\n");
    } else {
        s.push_str("stack:\n");
    }
    for i in items {
        if let Some(p) = &i.product {
            let _ = writeln!(s, "  - product: {p}");
            let _ = writeln!(
                s,
                "    version: {}",
                quote(i.version.as_deref().unwrap_or_default())
            );
        } else if let Some(p) = &i.purl {
            let _ = writeln!(s, "  - purl: {}", quote(p));
        }
        if i.internet {
            s.push_str("    exposure: internet\n");
        }
        if let Some(n) = &i.name {
            let _ = writeln!(s, "    name: {}", quote(n));
        }
    }
    s.push_str("\n# Where findings go. GitHub issues need no secret.\nnotify:\n  issues: true\n\n# Day of the weekly digest (monday ... sunday, or daily).\ndigest: monday\n\n# Accept a risk on purpose (`until` is required):\n# ignore:\n#   - cve: CVE-2024-1234\n#     reason: \"The app is disabled\"\n#     until: 2027-01-31\n");
    s
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use unpatched_core::Config;

    use super::*;

    #[test]
    fn the_templates_are_valid() {
        let cfg = Config::from_yaml(CONFIG_TEMPLATE).unwrap();
        for item in &cfg.stack {
            if let Some(p) = &item.product {
                assert!(unpatched_catalog::get(p).is_some(), "{p}");
            }
        }
    }

    #[test]
    fn the_templates_match_the_copies_in_the_repository() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/github");
        for (file, text) in [
            ("unpatched.yml", CONFIG_TEMPLATE),
            ("workflow.yml", WORKFLOW_TEMPLATE),
        ] {
            if let Ok(repo) = std::fs::read_to_string(root.join(file)) {
                assert_eq!(
                    repo, text,
                    "templates/github/{file} and crates/unpatched/templates/{file} differ; copy one over the other"
                );
            }
        }
    }

    #[test]
    fn answers_become_a_valid_config() {
        let answers = "fortigate\n7.2.5\ny\nOffice firewall\npostgresql\n15.4\n\n\nnextclou\n1\n29.0.3\n\n\npkg:deb/debian/openssl@3.0.11-1~deb12u1\n\n";
        let mut input = Cursor::new(answers.as_bytes());
        let mut output = Vec::new();
        let text = interactive(&mut input, &mut output).unwrap();
        let cfg = Config::from_yaml(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert_eq!(cfg.stack.len(), 4, "{text}");
        assert_eq!(cfg.stack[0].product.as_deref(), Some("fortios"));
        assert_eq!(cfg.stack[0].name.as_deref(), Some("Office firewall"));
        assert_eq!(cfg.stack[1].version.as_deref(), Some("15.4"));
        assert_eq!(cfg.stack[2].product.as_deref(), Some("nextcloud"));
        assert!(cfg.stack[3].purl.is_some());
    }

    #[test]
    fn no_answers_still_parse() {
        let mut input = Cursor::new(b"\n".as_slice());
        let mut output = Vec::new();
        let text = interactive(&mut input, &mut output).unwrap();
        Config::from_yaml(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    }
}
