use super::{FileAlias, canonicalize, canonicalize_file_aliases, fold_path, rewrite};
use crate::sandbox::SandboxCommand;
use std::path::PathBuf;

fn fixture() -> (tempfile::TempDir, PathBuf, FileAlias) {
    fixture_named("physical-tools")
}

fn fixture_named(physical_name: &str) -> (tempfile::TempDir, PathBuf, FileAlias) {
    let root = tempfile::tempdir().unwrap();
    let tools = root.path().join(physical_name);
    let alias = root.path().join("alias-tools");
    std::fs::create_dir(&tools).unwrap();
    std::fs::write(tools.join("worker.exe"), b"fixture").unwrap();
    std::os::windows::fs::symlink_dir(&tools, &alias).unwrap();
    let executable = alias.join("worker.exe");
    let canonical = canonicalize(&executable).unwrap();
    let record = FileAlias {
        original: fold_path(executable.to_str().unwrap()),
        replacement: canonical.to_str().unwrap().to_string(),
        canonical,
    };
    (root, executable, record)
}

#[test]
fn rewrites_verified_file_aliases_in_commands_and_compound_values() {
    let (_root, executable, alias) = fixture();
    let spelling = executable.to_str().unwrap();
    let input = format!("\"{spelling}\" & -Dworker=\"{spelling}\";{spelling}");
    let expected = format!(
        "\"{}\" & -Dworker=\"{}\";{}",
        alias.replacement, alias.replacement, alias.replacement
    );
    assert_eq!(rewrite(&input, &[alias], false).unwrap(), expected);
}

#[test]
fn verifies_case_and_separator_variants_against_the_filesystem() {
    let (_root, executable, alias) = fixture();
    let spelling = executable
        .to_str()
        .unwrap()
        .to_ascii_uppercase()
        .replace('\\', "/");
    assert_eq!(
        rewrite(&spelling, std::slice::from_ref(&alias), false).unwrap(),
        alias.replacement
    );
}

#[test]
fn does_not_rewrite_prefix_collisions_or_file_descendants() {
    let (_root, executable, alias) = fixture();
    let spelling = executable.to_str().unwrap();
    for input in [
        format!("prefix{spelling}"),
        format!("{spelling}-copy"),
        format!("{spelling}\\..\\sibling.exe"),
        format!("{spelling}/child"),
    ] {
        assert_eq!(
            rewrite(&input, std::slice::from_ref(&alias), false).unwrap(),
            input
        );
    }
}

#[test]
fn replacements_are_not_reprocessed_as_aliases() {
    let (_root, executable, first) = fixture();
    let another = first.canonical.with_file_name("another.exe");
    std::fs::write(&another, b"different").unwrap();
    let second = FileAlias {
        original: fold_path(&first.replacement),
        canonical: another.clone(),
        replacement: another.to_str().unwrap().to_string(),
    };
    let expected = first.replacement.clone();
    assert_eq!(
        rewrite(executable.to_str().unwrap(), &[first, second], false).unwrap(),
        expected
    );
}

#[test]
fn rejects_retargeted_or_missing_aliases() {
    let (root, executable, alias) = fixture();
    let alias_root = executable.parent().unwrap();
    std::fs::remove_dir(alias_root).unwrap();
    assert!(
        rewrite(
            executable.to_str().unwrap(),
            std::slice::from_ref(&alias),
            false
        )
        .is_err()
    );
    let other = root.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("worker.exe"), b"untrusted").unwrap();
    std::os::windows::fs::symlink_dir(&other, alias_root).unwrap();
    let error = rewrite(executable.to_str().unwrap(), &[alias], false).unwrap_err();
    assert!(error.to_string().contains("changed its physical target"));
}

#[test]
fn rewrites_redirection_adjacent_file_aliases() {
    let (_root, executable, alias) = fixture();
    let input = format!(
        "{}>out.txt & type <{}",
        executable.display(),
        executable.display()
    );
    let expected = format!(
        "{}>out.txt & type <{}",
        alias.replacement, alias.replacement
    );
    assert_eq!(rewrite(&input, &[alias], false).unwrap(), expected);
}

#[test]
fn rejects_shell_sensitive_replacements_even_for_a_whole_or_quoted_argument() {
    for name in [
        "bin&echo OWNED&rem x",
        "physical tools",
        "bin%VAR%",
        "bin!VAR!",
        "bin^escape",
        "bin$expand",
    ] {
        let (_root, executable, alias) = fixture_named(name);
        let spelling = executable.to_str().unwrap();
        for input in [
            spelling.to_string(),
            format!("{spelling} arg"),
            format!("\"{spelling}\" arg"),
            format!("'{spelling}' arg"),
        ] {
            let error = rewrite(&input, std::slice::from_ref(&alias), false).unwrap_err();
            assert!(
                matches!(error, crate::sandbox::SandboxError::Invalid(message) if message.contains("unsupported command-string escaping"))
            );
        }
    }
}

#[test]
fn structured_program_path_does_not_use_shell_string_restrictions() {
    let (_root, executable, alias) = fixture_named("physical tools&data");
    assert_eq!(
        rewrite(
            executable.to_str().unwrap(),
            std::slice::from_ref(&alias),
            true
        )
        .unwrap(),
        alias.replacement
    );
    let complete_path = format!("{} arg", executable.display());
    assert_eq!(
        rewrite(&complete_path, &[alias], true).unwrap(),
        complete_path
    );
}

#[test]
fn unicode_text_preserves_rewrite_boundaries() {
    let (_root, executable, alias) = fixture();
    let input = format!("\u{03bb} \"{}\" \u{1f43d}", executable.display());
    let expected = format!("\u{03bb} \"{}\" \u{1f43d}", alias.replacement);
    assert_eq!(rewrite(&input, &[alias], false).unwrap(), expected);
}

fn command(root: PathBuf, executable: PathBuf) -> SandboxCommand {
    let spelling = executable.to_str().unwrap().to_string();
    SandboxCommand {
        root: root.clone(),
        workdir: PathBuf::from("."),
        program: spelling.clone(),
        args: vec![spelling.clone()],
        read_only_paths: vec![executable.clone()],
        writable_paths: Vec::new(),
        persistent_read_only_paths: Vec::new(),
        persistent_executable_paths: Vec::new(),
        executable_paths: vec![executable.clone()],
        windows_virtualized_paths: vec![root],
        env: vec![
            ("HOME".to_string(), spelling.clone()),
            ("localappdata".to_string(), spelling.clone()),
        ],
        allow_network: false,
        timeout: std::time::Duration::from_secs(1),
        output_limit: 1024,
        memory_limit: 1024,
        process_limit: 1,
    }
}

#[test]
fn leaves_grants_mapping_roots_and_local_app_data_unchanged() {
    let (root, executable, alias) = fixture();
    let spelling = executable.to_str().unwrap().to_string();
    let mut spec = command(root.path().to_path_buf(), executable.clone());
    canonicalize_file_aliases(&mut spec).unwrap();
    assert_eq!(spec.program, alias.replacement);
    assert_eq!(spec.args, vec![alias.replacement.clone()]);
    assert_eq!(spec.env[0].1, alias.replacement);
    assert_eq!(spec.env[1].1, spelling);
    assert_eq!(spec.read_only_paths, vec![executable.clone()]);
    assert_eq!(spec.executable_paths, vec![executable]);
    assert_eq!(
        spec.windows_virtualized_paths,
        vec![root.path().to_path_buf()]
    );
}

#[test]
fn physical_paths_normalize_separators_without_new_shell_syntax() {
    let (root, executable, alias) = fixture_named("physical tools&data");
    let canonical = canonicalize(&executable).unwrap();
    let mut spec = command(root.path().to_path_buf(), canonical.clone());
    let variant = canonical.to_str().unwrap().replace('\\', "/");
    spec.args = vec![variant.clone(), format!("\"{variant}\">out.txt")];
    spec.env[0].1 = variant;
    canonicalize_file_aliases(&mut spec).unwrap();
    assert_eq!(spec.program, alias.replacement);
    assert_eq!(
        spec.args,
        vec![
            alias.replacement.clone(),
            format!("\"{}\">out.txt", alias.replacement)
        ]
    );
    assert_eq!(spec.env[0].1, alias.replacement);
    assert_eq!(spec.executable_paths, vec![canonical]);
}

#[test]
fn structured_program_preserves_a_distinct_file_with_an_alias_prefix() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.exe");
    let alias = root.path().join("worker.exe");
    let selected = root.path().join("worker.exe backup.exe");
    std::fs::write(&target, b"declared runtime").unwrap();
    std::fs::write(&selected, b"different selected runtime").unwrap();
    std::os::windows::fs::symlink_file(&target, &alias).unwrap();
    let mut spec = command(root.path().to_path_buf(), alias);
    let expected = canonicalize(&selected)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    spec.program = expected.clone();
    canonicalize_file_aliases(&mut spec).unwrap();
    assert_eq!(spec.program, expected);
    assert_eq!(
        canonicalize(std::path::Path::new(&spec.program)).unwrap(),
        canonicalize(&selected).unwrap()
    );
}
