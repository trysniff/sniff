use super::IntentionalBoundaryProjectModelVariant;

pub(super) use crate::compiler_go_variants::{
    GO_VARIANT_LIMIT, GoConstraintTagDomain, go_project_model_pipeline_identity,
    parse_go_constraint_tags, stage_go_constraint_invocation,
};
pub(in crate::benchmark::release) use crate::compiler_go_variants::{
    go_architecture_environment_variable, valid_go_architecture_configuration,
};

pub(super) fn parse_go_dist_variants(
    stdout: &str,
    tag_domain: &GoConstraintTagDomain,
) -> Result<Vec<IntentionalBoundaryProjectModelVariant>, String> {
    crate::compiler_go_variants::parse_go_dist_variants(stdout, tag_domain).map(|contexts| {
        contexts
            .into_iter()
            .map(|context| IntentionalBoundaryProjectModelVariant::Go {
                goos: context.goos,
                goarch: context.goarch,
                cgo_enabled: context.cgo_enabled,
                build_tags: context.build_tags,
                architecture: context.architecture,
                query: context.query,
            })
            .collect()
    })
}
