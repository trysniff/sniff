use super::{directives, nearest_module_manifest};
use std::collections::BTreeSet;

#[test]
fn directive_census_matches_go_generate_line_rules() {
    let source = concat!(
        "package sample\n",
        "//go:generate go run ./cmd/tool\n",
        "\t//go:generate ignored\n",
        "//go:generate\tgo tool stringer\r\n",
        "var text = `\n",
        "//go:generate go run ./cmd/from_raw_string\n",
        "`\n",
    );

    let found = directives("pkg/input.go", source);

    assert_eq!(found.len(), 3);
    assert_eq!(found[0].location.start_line_zero_based, 1);
    assert_eq!(found[1].location.start_line_zero_based, 3);
    assert_eq!(found[2].location.start_line_zero_based, 5);
    assert_eq!(found[1].source_text, "//go:generate\tgo tool stringer");
}

#[test]
fn module_anchor_is_the_nearest_enclosing_go_mod() {
    let manifests = BTreeSet::from(["go.mod", "tools/go.mod", "tools/nested/go.mod"]);

    assert_eq!(
        nearest_module_manifest("tools/nested/pkg", &manifests),
        Some("tools/nested/go.mod".to_string())
    );
    assert_eq!(
        nearest_module_manifest("tools/other", &manifests),
        Some("tools/go.mod".to_string())
    );
    assert_eq!(
        nearest_module_manifest("pkg", &manifests),
        Some("go.mod".to_string())
    );
    assert_eq!(nearest_module_manifest("", &BTreeSet::new()), None);
}
