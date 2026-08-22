use super::*;

#[test]
fn reproduces_licensee_v9_19_0_root_filename_scores() {
    let cases = [
        ("license", 10_000),
        ("LICENCE", 10_000),
        ("unLICENSE", 10_000),
        ("unlicence", 10_000),
        ("license.md", 9_500),
        ("LICENSE.md", 9_500),
        ("license.txt", 9_500),
        ("COPYING", 9_000),
        ("copyRIGHT", 3_500),
        ("COPYRIGHT.txt", 3_000),
        ("copying.txt", 8_500),
        ("LICENSE.MPL-2.0", 8_000),
        ("LICENSE.php", 8_000),
        ("LICENCE.docs", 8_000),
        ("license.xml", 8_000),
        ("copying.image", 7_500),
        ("COPYING.textile", 7_500),
        ("LICENSE-MIT", 7_000),
        ("LICENSE_1_0.txt", 7_000),
        ("COPYING-GPL", 6_500),
        ("COPYING-MIT", 6_500),
        ("COPYRIGHT-BSD", 2_000),
        ("MIT-LICENSE.txt", 6_000),
        ("mit-license-foo.md", 6_000),
        ("MIT-COPYING", 5_500),
        ("OFL.md", 5_000),
        ("ofl.textile", 4_500),
        ("ofl", 4_000),
        ("COPYRIGHT.textile", 2_500),
        ("PATENTS", 1_500),
        ("PATENTS.txt", 1_000),
    ];

    for (filename, expected_score) in cases {
        assert_eq!(
            match_license_filename(filename)
                .unwrap_or_else(|| panic!("{filename} must match"))
                .score_basis_points,
            expected_score,
            "unexpected score for {filename}"
        );
    }
}

#[test]
fn reproduces_licensee_v9_19_0_root_filename_rejections() {
    for filename in [
        "not-the-ofl",
        "README.txt",
        ".pip-license-ignore",
        "license-checks.xml",
        "license_test.go",
        "licensee.gemspec",
        "LICENSE.spdx",
        "check_license.sh",
        "docs/LICENSE",
        "LICENSE.header",
    ] {
        assert_eq!(
            match_license_filename(filename),
            None,
            "{filename} must not match"
        );
    }
}

#[test]
fn reproduces_licensee_v9_19_0_licenses_directory_rules() {
    for filename in [
        "LICENSES/MIT.txt",
        "LICENSES/LicenseRef-MIT.txt",
        "LICENSES/LicenseRef-Custom-1.0.md",
        "LICENSES/0BSD.txt",
        "LICENSES/GPL-2.0.txt",
    ] {
        assert_eq!(
            match_license_filename(filename)
                .unwrap_or_else(|| panic!("{filename} must match"))
                .score_basis_points,
            10_000
        );
    }

    for filename in [
        "LICENSES/foo bar.md",
        "LICENSES/-MIT.txt",
        "LICENSES/.MIT.txt",
        "LICENSES/LicenseRef-.txt",
        "LICENSES/MIT",
        "licenses/MIT.txt",
        "LICENSES/nested/MIT.txt",
    ] {
        assert_eq!(
            match_license_filename(filename),
            None,
            "{filename} must not match"
        );
    }
}

#[test]
fn pins_the_exact_upstream_policy_identity() {
    assert_eq!(LICENSEE_RELEASE, "v9.19.0");
    assert_eq!(
        LICENSEE_COMMIT_SHA1,
        "0d960b6acae28aec57da7c2911180334b61af09d"
    );
    assert_eq!(
        LICENSEE_LICENSE_FILE_BLOB_SHA1,
        "c1dd2c4b2514740151f2bdc924c99b37649e2d9c"
    );
    assert!(INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT.contains(LICENSEE_COMMIT_SHA1));
    assert!(
        INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT.contains(LICENSEE_LICENSE_FILE_BLOB_SHA1)
    );
}
