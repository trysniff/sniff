pub fn normalize_path(p: &str) -> String {
    let mut normalized = p.replace('\\', "/");
    if normalized.starts_with("//?/") {
        normalized = normalized[4..].to_string();
    }

    let drive_prefix = normalized
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':')
        .then(|| normalized[..2].to_string());
    let absolute = normalized.starts_with('/')
        || drive_prefix
            .as_ref()
            .is_some_and(|_| normalized.as_bytes().get(2) == Some(&b'/'));
    let path_body = drive_prefix
        .as_ref()
        .map(|_| &normalized[2..])
        .unwrap_or(&normalized);
    let mut segments = Vec::new();
    for segment in path_body.split('/') {
        match segment {
            "" | "." => {}
            ".." if segments.last().is_some_and(|previous| *previous != "..") => {
                segments.pop();
            }
            ".." if !absolute => segments.push(segment),
            ".." => {}
            _ => segments.push(segment),
        }
    }

    let body = segments.join("/");
    match (drive_prefix, absolute, body.is_empty()) {
        (Some(drive), true, true) => format!("{drive}/"),
        (Some(drive), true, false) => format!("{drive}/{body}"),
        (Some(drive), false, true) => drive,
        (Some(drive), false, false) => format!("{drive}{body}"),
        (None, true, true) => "/".to_string(),
        (None, true, false) => format!("/{body}"),
        (None, false, _) => body,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn collapses_relative_parent_segments() {
        assert_eq!(
            normalize_path("repo/worker/src/routes/../core/state-gateway-client.ts"),
            "repo/worker/src/core/state-gateway-client.ts"
        );
    }

    #[test]
    fn preserves_drive_roots_while_collapsing_parent_segments() {
        assert_eq!(
            normalize_path(r"C:\repo\worker\src\routes\..\core\client.ts"),
            "C:/repo/worker/src/core/client.ts"
        );
    }

    #[test]
    fn preserves_unmatched_leading_parent_segments_for_relative_paths() {
        assert_eq!(
            normalize_path("../../src/./client.ts"),
            "../../src/client.ts"
        );
    }
}
