use super::normalize_windows_path;
use crate::sandbox::{SandboxCommand, SandboxError};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct SandboxDriveMapping {
    drive: String,
    root: PathBuf,
    active: bool,
}

impl SandboxDriveMapping {
    pub(super) fn create(root: &Path) -> Result<Self, SandboxError> {
        let root = normalize_windows_path(std::fs::canonicalize(root).map_err(|error| {
            SandboxError::Failed(format!(
                "resolve Windows sandbox root for private drive mapping failed: {error}"
            ))
        })?);
        let mut failures = Vec::new();
        for letter in ('D'..='Z').rev() {
            let drive = format!("{letter}:");
            if Path::new(&format!(r"{drive}\")).exists() {
                continue;
            }
            let output = Command::new("subst")
                .arg(&drive)
                .arg(&root)
                .output()
                .map_err(|error| {
                    SandboxError::Unavailable(format!(
                        "Windows private drive mapping requires subst.exe: {error}"
                    ))
                })?;
            if output.status.success() {
                return Ok(Self {
                    drive,
                    root,
                    active: true,
                });
            }
            failures.push(format!(
                "{drive}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Err(SandboxError::Failed(format!(
            "no private Windows sandbox drive could be mapped{}",
            if failures.is_empty() {
                String::new()
            } else {
                format!(": {}", failures.join("; "))
            }
        )))
    }

    pub(super) fn process_spec(&self, spec: &SandboxCommand) -> SandboxCommand {
        let mut process_spec = spec.clone();
        let original_root = normalize_windows_path(spec.root.clone());
        process_spec.root = PathBuf::from(format!(r"{}\", self.drive));
        process_spec.program = self.rewrite(&process_spec.program, &original_root);
        process_spec.args = process_spec
            .args
            .iter()
            .map(|argument| self.rewrite(argument, &original_root))
            .collect();
        process_spec.env = process_spec
            .env
            .iter()
            .map(|(name, value)| (name.clone(), self.rewrite(value, &original_root)))
            .collect();
        process_spec
    }

    fn rewrite(&self, value: &str, original_root: &Path) -> String {
        let value = rewrite_root_path(value, original_root, &self.drive);
        if original_root == self.root {
            value
        } else {
            rewrite_root_path(&value, &self.root, &self.drive)
        }
    }

    pub(super) fn remove(&mut self) -> Result<(), SandboxError> {
        if !self.active {
            return Ok(());
        }
        let output = Command::new("subst")
            .args([self.drive.as_str(), "/D"])
            .output()
            .map_err(|error| {
                SandboxError::Failed(format!(
                    "unmap private Windows sandbox drive {} failed: {error}",
                    self.drive
                ))
            })?;
        if !output.status.success() {
            return Err(SandboxError::Failed(format!(
                "unmap private Windows sandbox drive {} failed: {}",
                self.drive,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SandboxDriveMapping {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

fn rewrite_root_path(value: &str, root: &Path, drive: &str) -> String {
    let root = root.to_string_lossy();
    let root = root.trim_end_matches(['\\', '/']);
    if root.is_empty() {
        return value.to_string();
    }
    let lower_value = value.to_ascii_lowercase();
    let lower_root = root.to_ascii_lowercase();
    let mut rewritten = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(relative) = lower_value[cursor..].find(&lower_root) {
        let start = cursor + relative;
        let end = start + lower_root.len();
        let next = value[end..].chars().next();
        if !matches!(next, None | Some('\\' | '/' | ';' | '"' | '\'' | ' ')) {
            rewritten.push_str(&value[cursor..end]);
            cursor = end;
            continue;
        }
        rewritten.push_str(&value[cursor..start]);
        rewritten.push_str(drive);
        if !matches!(next, Some('\\' | '/')) {
            rewritten.push('\\');
        }
        cursor = end;
    }
    rewritten.push_str(&value[cursor..]);
    rewritten
}

#[cfg(test)]
mod tests {
    use super::rewrite_root_path;
    use std::path::Path;

    #[test]
    fn private_drive_rewrite_preserves_path_boundaries() {
        let root = Path::new(r"C:\work\repository");

        assert_eq!(rewrite_root_path(r"C:\work\repository", root, "Z:"), r"Z:\");
        assert_eq!(
            rewrite_root_path(
                r"-Dtarget=C:\WORK\REPOSITORY\build;C:\work\repository\cache",
                root,
                "Z:",
            ),
            r"-Dtarget=Z:\build;Z:\cache"
        );
        assert_eq!(
            rewrite_root_path(r"C:\work\repository-copy\file", root, "Z:"),
            r"C:\work\repository-copy\file"
        );
    }
}
