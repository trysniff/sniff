use super::super::history_v3_label_review::tests::review_fixture;
use super::super::{
    HistoricalV3ReviewerVerdict, audit_historical_v3_label_reviews,
    prepare_historical_v3_label_resolution, resolve_historical_v3_label,
    verify_historical_v3_final_review,
};
use super::{
    HistoricalV3OrderedRankOutcome, HistoricalV3OrderedStopStatus,
    evaluate_historical_v3_ordered_prefix,
};

#[tokio::test]
async fn verified_final_review_is_counted_at_its_exact_rank() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
    let worksheets = [
        fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Slop),
        fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Slop),
    ];
    let audit = audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
    let resolution =
        prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
            .unwrap();
    let label =
        resolve_historical_v3_label(&inputs, &fixture.bundle, &worksheets, &audit, &resolution)
            .unwrap();
    let proof = verify_historical_v3_final_review(
        &inputs,
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
        &label,
    )
    .unwrap();
    let language = inputs.qualification.rank.language();
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(inputs.protocol, inputs.collection, language, &[])
            .unwrap(),
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: 0,
            reviewed: 0,
            ..
        }
    ));
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            inputs.protocol,
            inputs.collection,
            language,
            &[HistoricalV3OrderedRankOutcome::Reviewed(proof)],
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::FailedSourceExhausted {
            processed_ranks: 1,
            reviewed: 1,
            accepted: 1,
            ..
        }
    ));
}
