use pep508_rs::{Requirement, VerbatimUrl, VersionOrUrl};
use std::str::FromStr;

pub(super) const PYPI_SIMPLE_INDEX: &str = "https://pypi.org/simple/";

pub(super) fn validate_python_build_requirement(requirement: &str) -> Result<(), String> {
    if requirement.is_empty()
        || requirement.trim() != requirement
        || requirement.chars().any(char::is_control)
    {
        return Err("Python build requirement is empty or contains unsafe whitespace".to_string());
    }
    let parsed = Requirement::<VerbatimUrl>::from_str(requirement)
        .map_err(|error| format!("invalid Python build requirement: {error}"))?;
    if matches!(parsed.version_or_url, Some(VersionOrUrl::Url(_))) {
        return Err("direct-URL Python build requirements are not allowed".to_string());
    }
    Ok(())
}

pub(super) fn validate_python_package_index(index: &str) -> Result<(), String> {
    if index == PYPI_SIMPLE_INDEX {
        return Ok(());
    }
    #[cfg(test)]
    {
        let url = reqwest::Url::parse(index)
            .map_err(|error| format!("invalid Python package index URL: {error}"))?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
        if url.scheme() == "http"
            && loopback
            && url.path() == "/simple/"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
        {
            return Ok(());
        }
    }
    Err("Python package index is not an allowed registry endpoint".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        PYPI_SIMPLE_INDEX, validate_python_build_requirement, validate_python_package_index,
    };

    #[test]
    fn accepts_pep508_registry_requirements() {
        for requirement in [
            "hatchling==1.27.0",
            "setuptools>=70",
            "wheel; python_version >= '3.11'",
            "setuptools[core]>=70",
        ] {
            validate_python_build_requirement(requirement).unwrap();
        }
    }

    #[test]
    fn rejects_pip_options_direct_urls_and_invalid_text() {
        for requirement in [
            "--extra-index-url https://example.invalid/simple",
            "-r outside.txt",
            "package @ https://example.invalid/package.whl",
            "../local-package",
            " package==1",
            "package==1\n--index-url https://example.invalid",
        ] {
            assert!(
                validate_python_build_requirement(requirement).is_err(),
                "unexpectedly accepted {requirement:?}"
            );
        }
    }

    #[test]
    fn package_index_is_fixed_except_for_loopback_tests() {
        validate_python_package_index(PYPI_SIMPLE_INDEX).unwrap();
        validate_python_package_index("http://127.0.0.1:8042/simple/").unwrap();
        for index in [
            "https://example.invalid/simple/",
            "http://127.0.0.1:8042/other/",
            "http://user@127.0.0.1:8042/simple/",
            "file:///tmp/simple/",
        ] {
            assert!(validate_python_package_index(index).is_err());
        }
    }
}
