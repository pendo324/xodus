//! Minimal writer for Wine's plain-text prefix registry files (`user.reg`/`system.reg`,
//! `WINE REGISTRY Version 2` format). Used instead of `reg.exe` wherever a caller needs to
//! seed or update a prefix's registry while Wine isn't running - starting `reg.exe` would
//! also start Wine Explorer, and could initialise a second GPU session, as an unwanted side
//! effect of what should be an offline setup step.

use std::io;
use std::path::Path;

pub(crate) enum RegValue {
    Sz(String),
    ExpandSz(String),
    Dword(u32),
}

pub(crate) struct RegChange {
    key: String,
    value_name: &'static str,
    value: RegValue,
}

impl RegChange {
    pub(crate) fn sz(key: &str, value_name: &'static str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value_name,
            value: RegValue::Sz(value.to_string()),
        }
    }
    pub(crate) fn expand_sz(key: &str, value_name: &'static str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value_name,
            value: RegValue::ExpandSz(value.to_string()),
        }
    }
    pub(crate) fn dword(key: &str, value_name: &'static str, value: u32) -> Self {
        Self {
            key: key.to_string(),
            value_name,
            value: RegValue::Dword(value),
        }
    }
}

fn escape_reg_key(key: &str) -> String {
    key.replace('\\', "\\\\")
}

fn escape_reg_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn format_reg_value_line(name: &str, value: &RegValue) -> String {
    match value {
        RegValue::Sz(s) => format!("\"{name}\"=\"{}\"", escape_reg_string(s)),
        RegValue::ExpandSz(s) => format!("\"{name}\"=str(2):\"{}\"", escape_reg_string(s)),
        RegValue::Dword(v) => format!("\"{name}\"=dword:{v:08x}"),
    }
}

/// Applies `changes` to a Wine `*.reg` file (`WINE REGISTRY Version 2` text format),
/// updating each named value in place if its key section already exists, or appending a new
/// section (with a fresh Unix-epoch/FILETIME timestamp pair, matching real sections) if not.
/// Written via a temp-file-then-rename so a crash mid-write can't corrupt the prefix's
/// registry.
pub(crate) fn apply_registry_changes(reg_path: &Path, changes: &[RegChange]) -> io::Result<()> {
    let mut text = std::fs::read_to_string(reg_path).unwrap_or_else(|_| {
        "WINE REGISTRY Version 2\n;; All keys relative to REGISTRY\\Machine\n\n#arch=win64\n\n"
            .to_string()
    });

    for group_key in changes
        .iter()
        .map(|c| c.key.as_str())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let group: Vec<&RegChange> = changes.iter().filter(|c| c.key == group_key).collect();
        upsert_registry_section(&mut text, group_key, &group);
    }

    let tmp = reg_path.with_extension("reg.xodus-tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::rename(&tmp, reg_path)?;
    Ok(())
}

fn upsert_registry_section(text: &mut String, key: &str, changes: &[&RegChange]) {
    let escaped = escape_reg_key(key);
    let header = format!("[{escaped}]");

    if let Some(start) = text.find(&header) {
        let section_body_start = text[start..]
            .find('\n')
            .map(|i| start + i + 1)
            .unwrap_or(text.len());
        let rest = &text[section_body_start..];
        let section_end = rest
            .find("\n[")
            .map(|i| section_body_start + i + 1)
            .unwrap_or(text.len());

        let mut body = text[section_body_start..section_end].to_string();
        for change in changes {
            let line = format_reg_value_line(change.value_name, &change.value);
            let needle = format!("\"{}\"=", change.value_name);
            if let Some(pos) = body.lines().position(|l| l.starts_with(&needle)) {
                let lines: Vec<&str> = body.lines().collect();
                let mut new_lines = lines.clone();
                new_lines[pos] = &line;
                body = new_lines.join("\n");
                body.push('\n');
            } else {
                if !body.ends_with('\n') {
                    body.push('\n');
                }
                body.push_str(&line);
                body.push('\n');
            }
        }
        text.replace_range(section_body_start..section_end, &body);
    } else {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if !text.ends_with("\n\n") {
            text.push('\n');
        }
        text.push_str(&format!("{header} {}\n", unix_epoch_now()));
        text.push_str(&format!("#time={:x}\n", unix_to_filetime(unix_epoch_now())));
        for change in changes {
            text.push_str(&format_reg_value_line(change.value_name, &change.value));
            text.push('\n');
        }
        text.push('\n');
    }
}

fn unix_epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Windows FILETIME: 100ns intervals since 1601-01-01, vs. Unix epoch 1970-01-01.
fn unix_to_filetime(unix_secs: u64) -> u64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    (unix_secs + EPOCH_DIFF_SECS) * 10_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_reg(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("xodus-wine-registry-test-{name}.reg"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn creates_missing_file_with_a_new_section() {
        let path = std::env::temp_dir().join("xodus-wine-registry-test-missing.reg");
        let _ = std::fs::remove_file(&path);

        apply_registry_changes(
            &path,
            &[RegChange::sz(
                r"Software\Wine\DllOverrides",
                "xgameruntime",
                "b,n",
            )],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("WINE REGISTRY Version 2"));
        assert!(text.contains(r#"[Software\\Wine\\DllOverrides]"#));
        assert!(text.contains(r#""xgameruntime"="b,n""#));
    }

    #[test]
    fn appends_a_new_value_to_an_existing_section() {
        let path = tmp_reg(
            "append",
            "WINE REGISTRY Version 2\n\n[Software\\\\Wine\\\\DllOverrides] 1700000000\n\
             #time=1dc0000000000000\n\"ole32\"=\"native,builtin\"\n\n",
        );

        apply_registry_changes(
            &path,
            &[RegChange::sz(
                r"Software\Wine\DllOverrides",
                "xgameruntime",
                "n",
            )],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(r#""ole32"="native,builtin""#),
            "must not clobber an existing unrelated value in the same section"
        );
        assert!(text.contains(r#""xgameruntime"="n""#));
    }

    #[test]
    fn updates_an_existing_value_in_place() {
        let path = tmp_reg(
            "update",
            "WINE REGISTRY Version 2\n\n[Software\\\\Wine\\\\DllOverrides] 1700000000\n\
             #time=1dc0000000000000\n\"xgameruntime\"=\"n\"\n\n",
        );

        apply_registry_changes(
            &path,
            &[RegChange::sz(
                r"Software\Wine\DllOverrides",
                "xgameruntime",
                "b,n",
            )],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.matches("\"xgameruntime\"=").count(),
            1,
            "must replace the value in place, not append a duplicate"
        );
        assert!(text.contains(r#""xgameruntime"="b,n""#));
    }
}
