use super::IntentionalBoundaryLicenseFilenameRule;

pub const LICENSEE_RELEASE: &str = "v9.19.0";
pub const LICENSEE_COMMIT_SHA1: &str = "0d960b6acae28aec57da7c2911180334b61af09d";
pub const LICENSEE_LICENSE_FILE_BLOB_SHA1: &str = "c1dd2c4b2514740151f2bdc924c99b37649e2d9c";
pub const INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT: &str = "licensee-v9.19.0-name-score@0d960b6acae28aec57da7c2911180334b61af09d/c1dd2c4b2514740151f2bdc924c99b37649e2d9c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LicenseFilenameMatch {
    pub rule: IntentionalBoundaryLicenseFilenameRule,
    pub score_basis_points: u16,
}

pub(super) fn match_license_filename(path: &str) -> Option<LicenseFilenameMatch> {
    if let Some(filename) = path.strip_prefix("LICENSES/") {
        if filename.contains('/') {
            return None;
        }
        return match_licenses_directory_filename(filename);
    }
    if path.contains('/') {
        return None;
    }
    match_root_filename(path)
}

fn match_root_filename(filename: &str) -> Option<LicenseFilenameMatch> {
    let name = filename.to_ascii_lowercase();
    if is_license_base(&name) {
        return matched(IntentionalBoundaryLicenseFilenameRule::RootLicense, 10_000);
    }
    if strip_base_with_preferred_extension(&name, is_license_base).is_some() {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootLicensePreferredExtension,
            9_500,
        );
    }
    if name == "copying" {
        return matched(IntentionalBoundaryLicenseFilenameRule::RootCopying, 9_000);
    }
    if strip_exact_base_with_preferred_extension(&name, "copying").is_some() {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyingPreferredExtension,
            8_500,
        );
    }
    if split_base_suffix(&name, is_license_base)
        .is_some_and(|suffix| valid_extension(suffix, &["spdx", "header"]))
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootLicenseOtherExtension,
            8_000,
        );
    }
    if name
        .strip_prefix("copying")
        .is_some_and(|suffix| valid_extension(suffix, &[]))
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyingAnyExtension,
            7_500,
        );
    }
    if split_base_suffix(&name, is_license_base).is_some_and(valid_descriptor_suffix) {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootLicenseDescriptor,
            7_000,
        );
    }
    if name
        .strip_prefix("copying")
        .is_some_and(valid_descriptor_suffix)
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyingDescriptor,
            6_500,
        );
    }
    if valid_prefixed_base(&name, is_license_base) {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootPrefixedLicense,
            6_000,
        );
    }
    if valid_prefixed_base(&name, |value| value == "copying") {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootPrefixedCopying,
            5_500,
        );
    }
    if strip_exact_base_with_preferred_extension(&name, "ofl").is_some() {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootOflPreferredExtension,
            5_000,
        );
    }
    if name
        .strip_prefix("ofl")
        .is_some_and(|suffix| valid_extension(suffix, &["xml", "sh", "go", "gemspec"]))
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootOflOtherExtension,
            4_500,
        );
    }
    if name == "ofl" {
        return matched(IntentionalBoundaryLicenseFilenameRule::RootOfl, 4_000);
    }
    if name == "copyright" {
        return matched(IntentionalBoundaryLicenseFilenameRule::RootCopyright, 3_500);
    }
    if strip_exact_base_with_preferred_extension(&name, "copyright").is_some() {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyrightPreferredExtension,
            3_000,
        );
    }
    if name
        .strip_prefix("copyright")
        .is_some_and(|suffix| valid_extension(suffix, &["xml", "sh", "go", "gemspec"]))
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyrightOtherExtension,
            2_500,
        );
    }
    if name
        .strip_prefix("copyright")
        .is_some_and(valid_descriptor_suffix)
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootCopyrightDescriptor,
            2_000,
        );
    }
    if name == "patents" {
        return matched(IntentionalBoundaryLicenseFilenameRule::RootPatents, 1_500);
    }
    if name
        .strip_prefix("patents")
        .is_some_and(|suffix| valid_extension(suffix, &["xml", "sh", "go", "gemspec"]))
    {
        return matched(
            IntentionalBoundaryLicenseFilenameRule::RootPatentsOtherExtension,
            1_000,
        );
    }
    None
}

fn match_licenses_directory_filename(filename: &str) -> Option<LicenseFilenameMatch> {
    let (stem, extension) = filename.rsplit_once('.')?;
    if !is_preferred_extension(extension) {
        return None;
    }
    if let Some(reference) = stem
        .to_ascii_lowercase()
        .strip_prefix("licenseref-")
        .map(str::to_string)
    {
        return valid_identifier(&reference, true).then_some(LicenseFilenameMatch {
            rule: IntentionalBoundaryLicenseFilenameRule::LicensesLicenseRef,
            score_basis_points: 10_000,
        });
    }
    valid_identifier(stem, false).then_some(LicenseFilenameMatch {
        rule: IntentionalBoundaryLicenseFilenameRule::LicensesSpdxLike,
        score_basis_points: 10_000,
    })
}

fn split_base_suffix(value: &str, is_base: impl Fn(&str) -> bool) -> Option<&str> {
    ["unlicense", "unlicence", "license", "licence"]
        .into_iter()
        .find_map(|base| value.strip_prefix(base).filter(|_| is_base(base)))
}

fn strip_base_with_preferred_extension(
    value: &str,
    is_base: impl Fn(&str) -> bool,
) -> Option<&str> {
    split_base_suffix(value, is_base).filter(|suffix| preferred_extension(suffix).is_some())
}

fn strip_exact_base_with_preferred_extension<'a>(value: &'a str, base: &str) -> Option<&'a str> {
    value
        .strip_prefix(base)
        .filter(|suffix| preferred_extension(suffix).is_some())
}

fn preferred_extension(value: &str) -> Option<&str> {
    let extension = value.strip_prefix('.')?;
    is_preferred_extension(extension).then_some(extension)
}

fn is_preferred_extension(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "md" | "markdown" | "txt" | "html"
    )
}

fn valid_descriptor_suffix(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(['-', '_']) else {
        return false;
    };
    let (descriptor, extension) = rest.split_once('.').unwrap_or((rest, ""));
    if descriptor.contains('.') {
        return false;
    }
    extension.is_empty()
        || valid_extension(&format!(".{extension}"), &["xml", "sh", "go", "gemspec"])
}

fn valid_prefixed_base(value: &str, is_base: impl Fn(&str) -> bool) -> bool {
    value.char_indices().any(|(index, character)| {
        if !matches!(character, '-' | '_') || index == 0 {
            return false;
        }
        let prefix = &value[..index];
        if !prefix
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return false;
        }
        let remainder = &value[index + character.len_utf8()..];
        let Some(base_end) = ["unlicense", "unlicence", "license", "licence", "copying"]
            .into_iter()
            .find(|base| is_base(base) && remainder.starts_with(base))
            .map(str::len)
        else {
            return false;
        };
        let suffix = &remainder[base_end..];
        let (descriptor, extension) = suffix.split_once('.').unwrap_or((suffix, ""));
        !descriptor.contains('.')
            && (extension.is_empty()
                || valid_extension(&format!(".{extension}"), &["xml", "sh", "go", "gemspec"]))
    })
}

fn valid_extension(value: &str, excluded_prefixes: &[&str]) -> bool {
    let Some(extension) = value.strip_prefix('.') else {
        return false;
    };
    if extension.is_empty()
        || excluded_prefixes
            .iter()
            .any(|excluded| extension.starts_with(excluded))
    {
        return false;
    }
    let mut characters = extension.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '/' {
            return false;
        }
        if character == '.' && !characters.next().is_some_and(|next| next.is_ascii_digit()) {
            return false;
        }
    }
    true
}

fn valid_identifier(value: &str, license_ref: bool) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let remaining = characters.collect::<Vec<_>>();
    if remaining.is_empty() {
        return true;
    }
    if !remaining
        .iter()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    {
        return false;
    }
    remaining
        .last()
        .is_some_and(|last| last.is_ascii_alphanumeric())
        && (!license_ref || remaining.iter().all(|character| *character != '_'))
}

fn is_license_base(value: &str) -> bool {
    matches!(value, "license" | "licence" | "unlicense" | "unlicence")
}

fn matched(
    rule: IntentionalBoundaryLicenseFilenameRule,
    score_basis_points: u16,
) -> Option<LicenseFilenameMatch> {
    Some(LicenseFilenameMatch {
        rule,
        score_basis_points,
    })
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_license_filename_tests.rs"]
mod tests;
