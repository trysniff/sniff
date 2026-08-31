use super::super::{BenchmarkCommand, CliArgs, CliCommand};
use clap::Parser;

#[test]
fn parses_historical_v2_source_review_commands() {
    let prepare = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "prepare-historical-v2-source-review",
        "protocol.json",
        "artifact",
        "frame.json",
        "exclusions.json",
        "selection.json",
        "payloads.json",
        "state",
        "work",
        "harness",
        "rust",
        "7",
        "review-bundle",
    ])
    .expect("historical-v2 source review preparation arguments");
    let Some(CliCommand::Benchmark {
        command: BenchmarkCommand::PrepareHistoricalV2SourceReview(arguments),
    }) = prepare.command
    else {
        panic!("expected historical-v2 source review preparation command");
    };
    assert_eq!(arguments.protocol, "protocol.json");
    assert_eq!(arguments.artifact_root, "artifact");
    assert_eq!(arguments.frame, "frame.json");
    assert_eq!(arguments.exclusions, "exclusions.json");
    assert_eq!(arguments.selection, "selection.json");
    assert_eq!(arguments.payloads, "payloads.json");
    assert_eq!(arguments.state_root, "state");
    assert_eq!(arguments.work_root, "work");
    assert_eq!(arguments.harness_repository_root, "harness");
    assert_eq!(arguments.language, "rust");
    assert_eq!(arguments.slot_number.get(), 7);
    assert_eq!(arguments.output_directory, "review-bundle");

    let validate = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "validate-historical-v2-source-review",
        "protocol.json",
        "review-bundle",
    ])
    .expect("historical-v2 source review validation arguments");
    assert!(matches!(
        validate.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::ValidateHistoricalV2SourceReview {
                protocol,
                bundle_directory,
            }
        }) if protocol == "protocol.json" && bundle_directory == "review-bundle"
    ));
}

#[test]
fn parses_historical_v2_label_lifecycle_commands() {
    let prepare = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "prepare-historical-v2-labels",
        "protocol.json",
        "review-bundle",
        "blank.json",
    ])
    .expect("historical-v2 label preparation arguments");
    assert!(matches!(
        prepare.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::PrepareHistoricalV2Labels {
                protocol,
                bundle_directory,
                output,
            }
        }) if protocol == "protocol.json"
            && bundle_directory == "review-bundle"
            && output == "blank.json"
    ));

    let validate = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "validate-historical-v2-labels",
        "protocol.json",
        "review-bundle",
        "review-a.json",
    ])
    .expect("historical-v2 label validation arguments");
    assert!(matches!(
        validate.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::ValidateHistoricalV2Labels {
                protocol,
                bundle_directory,
                review,
            }
        }) if protocol == "protocol.json"
            && bundle_directory == "review-bundle"
            && review == "review-a.json"
    ));

    let audit = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "audit-historical-v2-labels",
        "protocol.json",
        "review-bundle",
        "audit.json",
        "--review",
        "review-a.json",
        "--review",
        "review-b.json",
    ])
    .expect("historical-v2 label audit arguments");
    assert!(matches!(
        audit.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::AuditHistoricalV2Labels {
                protocol,
                bundle_directory,
                output,
                reviews,
            }
        }) if protocol == "protocol.json"
            && bundle_directory == "review-bundle"
            && output == "audit.json"
            && reviews == ["review-a.json", "review-b.json"]
    ));

    let prepare_resolution = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "prepare-historical-v2-resolution",
        "protocol.json",
        "review-bundle",
        "audit.json",
        "resolution.json",
        "--review",
        "review-a.json",
        "--review",
        "review-b.json",
    ])
    .expect("historical-v2 resolution preparation arguments");
    assert!(matches!(
        prepare_resolution.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::PrepareHistoricalV2Resolution {
                protocol,
                bundle_directory,
                audit,
                output,
                reviews,
            }
        }) if protocol == "protocol.json"
            && bundle_directory == "review-bundle"
            && audit == "audit.json"
            && output == "resolution.json"
            && reviews == ["review-a.json", "review-b.json"]
    ));

    let resolve = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "resolve-historical-v2-labels",
        "protocol.json",
        "review-bundle",
        "audit.json",
        "resolution.json",
        "final-label.json",
        "--review",
        "review-a.json",
        "--review",
        "review-b.json",
    ])
    .expect("historical-v2 label resolution arguments");
    assert!(matches!(
        resolve.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::ResolveHistoricalV2Labels {
                protocol,
                bundle_directory,
                audit,
                resolution,
                output,
                reviews,
            }
        }) if protocol == "protocol.json"
            && bundle_directory == "review-bundle"
            && audit == "audit.json"
            && resolution == "resolution.json"
            && output == "final-label.json"
            && reviews == ["review-a.json", "review-b.json"]
    ));
}

#[test]
fn parses_historical_v2_aggregate_release_commands() {
    let arguments = [
        "protocol.json",
        "artifact",
        "frame.json",
        "exclusions.json",
        "selection.json",
        "state",
        "corpus",
        "release-evidence.json",
    ];
    let build = CliArgs::try_parse_from(
        ["sniff", "benchmark", "build-historical-v2-release-evidence"]
            .into_iter()
            .chain(arguments),
    )
    .expect("historical-v2 release evidence build arguments");
    let Some(CliCommand::Benchmark {
        command: BenchmarkCommand::BuildHistoricalV2ReleaseEvidence(arguments),
    }) = build.command
    else {
        panic!("expected historical-v2 release evidence build command");
    };
    assert_eq!(arguments.protocol, "protocol.json");
    assert_eq!(arguments.artifact_root, "artifact");
    assert_eq!(arguments.frame, "frame.json");
    assert_eq!(arguments.exclusions, "exclusions.json");
    assert_eq!(arguments.selection, "selection.json");
    assert_eq!(arguments.state_root, "state");
    assert_eq!(arguments.corpus_root, "corpus");
    assert_eq!(arguments.evidence, "release-evidence.json");

    let validate = CliArgs::try_parse_from(
        [
            "sniff",
            "benchmark",
            "validate-historical-v2-release-evidence",
        ]
        .into_iter()
        .chain(arguments_for_aggregate()),
    )
    .expect("historical-v2 release evidence validation arguments");
    assert!(matches!(
        validate.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::ValidateHistoricalV2ReleaseEvidence(_)
        })
    ));
}

#[test]
fn parses_historical_v2_corpus_publication_commands() {
    let publish = CliArgs::try_parse_from(
        ["sniff", "benchmark", "publish-historical-v2-corpus"]
            .into_iter()
            .chain(arguments_for_aggregate())
            .chain(["corpus-bundle.json"]),
    )
    .expect("historical-v2 corpus publication arguments");
    let Some(CliCommand::Benchmark {
        command: BenchmarkCommand::PublishHistoricalV2Corpus(arguments),
    }) = publish.command
    else {
        panic!("expected historical-v2 corpus publication command");
    };
    assert_eq!(arguments.output, "corpus-bundle.json");

    let validate = CliArgs::try_parse_from([
        "sniff",
        "benchmark",
        "validate-historical-v2-corpus",
        "protocol.json",
        "corpus",
        "corpus-bundle.json",
    ])
    .expect("historical-v2 corpus validation arguments");
    assert!(matches!(
        validate.command,
        Some(CliCommand::Benchmark {
            command: BenchmarkCommand::ValidateHistoricalV2Corpus {
                protocol,
                corpus_root,
                bundle,
            }
        }) if protocol == "protocol.json"
            && corpus_root == "corpus"
            && bundle == "corpus-bundle.json"
    ));
}

fn arguments_for_aggregate() -> [&'static str; 8] {
    [
        "protocol.json",
        "artifact",
        "frame.json",
        "exclusions.json",
        "selection.json",
        "state",
        "corpus",
        "release-evidence.json",
    ]
}
