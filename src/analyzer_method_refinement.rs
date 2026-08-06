use super::*;

pub(crate) async fn refine_scoped_construct_if_needed(
    analyzer: &Analyzer,
    method: &MethodRecord,
    review: SemanticMethodReview,
    file_context: &str,
    stale_discard_signature_proof: Option<&StaleDiscardSignatureProof>,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(SemanticMethodReview, usize, usize), String> {
    let (review, mut input_tokens, mut output_tokens) =
        refine_duplicated_branch_if_needed(analyzer, method, review, file_context, on_progress)
            .await?;
    let (review, discard_input, discard_output) = refine_parameter_discard_if_needed(
        analyzer,
        method,
        review,
        file_context,
        stale_discard_signature_proof,
        on_progress,
    )
    .await?;
    input_tokens += discard_input;
    output_tokens += discard_output;
    Ok((review, input_tokens, output_tokens))
}

pub(crate) fn proven_private_unused_review(
    method: &MethodRecord,
    scoped: SemanticMethodReview,
    coordinated_signature_removal: bool,
) -> SemanticMethodReview {
    let (contract_impact, simplification, change_scope) = if coordinated_signature_removal {
        (
            "Removing the unused implementation and its matching private contract surface leaves no callable or protocol contract behind.",
            "Delete the method and its matching private contract surface entry.",
            "signature",
        )
    } else {
        (
            "Deleting this repository-private unused method changes no callable or protocol contract.",
            "Delete the entire method.",
            "whole_method",
        )
    };
    SemanticMethodReview {
        tier: scoped.tier,
        pattern: scoped.pattern,
        intent: scoped.intent,
        reason: "The repository-private method has no consumer or boundary role and is dead conceptual machinery."
            .to_string(),
        evidence: vec![SemanticEvidence {
            start_line: method.start_line,
            end_line: method.end_line,
            quote: method.source.clone(),
        }],
        necessity_check:
            "The complete dossier establishes no repository consumer or boundary role for this method."
                .to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: contract_impact.to_string(),
        dependency_impact: "The closed repository graph has no caller, test, registration, export, callback, re-export, compatibility path, or protocol dependency."
            .to_string(),
        simplification: simplification.to_string(),
        change_scope: change_scope.to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    }
}

pub(crate) fn private_unused_requires_signature_change(file_context: &str) -> bool {
    file_context.lines().any(|line| {
        (line.starts_with(
            "matching private type/interface surface declarations requiring coordinated removal: ",
        ) && !line.ends_with("none established"))
            || line.starts_with(
                "private returned-object surface entries requiring coordinated removal: ",
            )
    })
}

pub(super) fn needs_private_unused_refinement(
    review: &SemanticMethodReview,
    repository_private_unused_candidate: bool,
) -> bool {
    repository_private_unused_candidate
        && matches!(review.tier, FindingTier::Clean | FindingTier::Unresolved)
}

pub(crate) async fn refine_private_unused_if_needed(
    analyzer: &Analyzer,
    method: &MethodRecord,
    review: SemanticMethodReview,
    file_context: &str,
    repository_private_unused_candidate: bool,
    coordinated_signature_removal: bool,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(SemanticMethodReview, usize, usize), String> {
    if !needs_private_unused_refinement(&review, repository_private_unused_candidate) {
        return Ok((review, 0, 0));
    }

    if let Some(callback) = on_progress {
        callback(ReviewProgress::RetryingEvidence {
            label: format!("resolving proven private-unused severity: {}", method.name),
        });
    }
    let proven_removal = if coordinated_signature_removal {
        "coordinated removal of the implementation and its matching private contract surface"
    } else {
        "whole-method deletion"
    };
    let prompt = format!(
        "You are the final severity judge for a deterministically proven private-unused method. Sniff's closed repository graph established zero callers, lexical candidates, tests, exports, registrations, callbacks, re-exports, compatibility paths, protocol roles, and role-based external consumers. Necessity and behavior-preserving {proven_removal} are already proven; do not ask for a hypothetical caller and do not return Clean or Unresolved. Judge only cognitive friction. Return `slop` when the dead method meaningfully adds misleading conceptual machinery, or `kinda_slop` when it is tiny and locally harmless.\n\nMethod: {}\nLanguage: {}\nFile: {}\nLines: {}-{}\n\nTyped repository dossier:\n---\n{}\n---\n\nMethod source:\n---\n{}\n---\n\nReturn exactly one JSON object: {{\"tier\":\"slop | kinda_slop\",\"reason\":\"one precise sentence about the cognitive friction\"}}",
        method.name,
        method.language,
        method.file_path,
        method.start_line,
        method.end_line,
        compact_method_context(file_context),
        numbered_method_source(method),
    );
    let (result, input_tokens, output_tokens) = analyzer
        .llm_client
        .call_single(&prompt, ResponseSchema::ScopedTierReview)
        .await?;
    let Some(result) = result else {
        return Ok((
            unresolved_construct_adjudication(
                &review,
                "AI did not classify the proven private-unused method's cognitive friction.",
            ),
            input_tokens,
            output_tokens,
        ));
    };
    let tier = match result.get("tier").and_then(serde_json::Value::as_str) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        _ => {
            return Ok((
                unresolved_construct_adjudication(
                    &review,
                    "AI returned no valid severity for the proven private-unused method.",
                ),
                input_tokens,
                output_tokens,
            ));
        }
    };
    let mut scoped = review;
    scoped.tier = tier;
    scoped.pattern = crate::product_contract::SlopPattern::ResidualMachinery;
    scoped.reason = result
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("The dead private method adds unnecessary cognitive friction.")
        .to_string();
    scoped.change_scope = if coordinated_signature_removal {
        "signature"
    } else {
        "whole_method"
    }
    .to_string();
    Ok((scoped, input_tokens, output_tokens))
}

async fn refine_duplicated_branch_if_needed(
    analyzer: &Analyzer,
    method: &MethodRecord,
    review: SemanticMethodReview,
    file_context: &str,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(SemanticMethodReview, usize, usize), String> {
    if matches!(review.tier, FindingTier::Slop | FindingTier::KindaSlop)
        && review.change_scope == "local"
    {
        return Ok((review, 0, 0));
    }
    let Some(duplicated_branch) = super::super::dossier::duplicated_branch_construct(method) else {
        return Ok((review, 0, 0));
    };
    if let Some(callback) = on_progress {
        callback(ReviewProgress::RetryingEvidence {
            label: format!(
                "scoped duplicated branch: method {}::{}",
                method.file_path, method.name
            ),
        });
    }
    let prompt = format!(
        "You are judging the severity of a structurally proven behavior-neutral branch. Sniff established that every path in the identified construct executes the same single statement, so replacing the branch with that statement preserves the callable contract and observable behavior. Judge only its cognitive friction. Return `slop` when the fake decision meaningfully obscures intent, `kinda_slop` when the ceremony is minor, `clean` only when the redundant branch communicates a concrete necessary domain distinction established by the dossier, or `unresolved` only when severity cannot be assessed.\n\nFile: {}\nMethod: {}\nLanguage: {}\nEvidence line range: {} through {}\n\nComplete repository dossier:\n---\n{}\n---\n\nMethod source:\n---\n{}\n---\n\nStructurally verified identical-branch construct:\n---\n{}\n---\n\nReturn exactly one JSON object: {{\"tier\":\"slop | kinda_slop | clean | unresolved\",\"reason\":\"one precise sentence about cognitive friction\"}}",
        method.file_path,
        method.name,
        method.language,
        method.start_line,
        method.end_line,
        file_context,
        numbered_method_source(method),
        duplicated_branch,
    );
    let (result, input_tokens, output_tokens) = analyzer
        .llm_client
        .call_single(&prompt, ResponseSchema::ScopedTierReview)
        .await?;
    let Some(result) = result else {
        return Ok((
            unresolved_construct_adjudication(
                &review,
                "AI did not classify the proven duplicated branch.",
            ),
            input_tokens,
            output_tokens,
        ));
    };
    let reason = result
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("The AI severity judgment did not include a usable reason.")
        .to_string();
    let resolved = match result.get("tier").and_then(serde_json::Value::as_str) {
        Some("slop") => proven_duplicated_branch_review(
            method,
            &review,
            &duplicated_branch,
            FindingTier::Slop,
            reason,
        ),
        Some("kinda_slop") => proven_duplicated_branch_review(
            method,
            &review,
            &duplicated_branch,
            FindingTier::KindaSlop,
            reason,
        ),
        Some("clean") => review,
        _ => unresolved_construct_adjudication(
            &review,
            "AI could not classify the proven duplicated branch's cognitive friction.",
        ),
    };
    Ok((resolved, input_tokens, output_tokens))
}

fn construct_evidence(method: &MethodRecord, construct: &str) -> SemanticEvidence {
    let method_lines = method.source.lines().collect::<Vec<_>>();
    let construct_lines = construct.lines().collect::<Vec<_>>();
    let start = method_lines
        .windows(construct_lines.len())
        .position(|window| window == construct_lines)
        .unwrap_or(0);
    SemanticEvidence {
        start_line: method.start_line + start,
        end_line: method.start_line + start + construct_lines.len().saturating_sub(1),
        quote: construct.to_string(),
    }
}

fn shared_branch_statement(construct: &str) -> String {
    construct
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("if ")
                && *line != "else:"
                && !line.starts_with("} else")
                && *line != "{"
                && *line != "}"
        })
        .unwrap_or("the shared statement")
        .trim_end_matches(';')
        .to_string()
}

fn proven_duplicated_branch_review(
    method: &MethodRecord,
    review: &SemanticMethodReview,
    duplicated_branch: &str,
    tier: FindingTier,
    reason: String,
) -> SemanticMethodReview {
    let shared_statement = shared_branch_statement(duplicated_branch);
    SemanticMethodReview {
        tier,
        pattern: crate::product_contract::SlopPattern::DuplicatedSemantics,
        intent: review.intent.clone(),
        reason,
        evidence: vec![construct_evidence(method, duplicated_branch)],
        necessity_check:
            "Structural analysis proves every path executes the same single statement.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact:
            "The callable signature, return behavior, and side effects remain unchanged."
                .to_string(),
        dependency_impact:
            "No caller can observe a distinction between behaviorally identical paths.".to_string(),
        simplification: format!("Replace the duplicated branch with `{shared_statement}`."),
        change_scope: "local".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    }
}

fn unresolved_construct_adjudication(
    review: &SemanticMethodReview,
    reason: &str,
) -> SemanticMethodReview {
    SemanticMethodReview {
        tier: FindingTier::Unresolved,
        pattern: crate::product_contract::SlopPattern::None,
        intent: review.intent.clone(),
        reason: reason.to_string(),
        evidence: Vec::new(),
        necessity_check: "The construct's severity was not resolved by AI adjudication."
            .to_string(),
        contract_status: "unknown".to_string(),
        contract_impact: "The final slop classification remains unknown.".to_string(),
        dependency_impact:
            "Repository dependency evidence is complete, but severity is unresolved.".to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "unknown".to_string(),
        missing_evidence: vec!["valid AI severity judgment".to_string()],
    }
}

async fn refine_parameter_discard_if_needed(
    analyzer: &Analyzer,
    method: &MethodRecord,
    review: SemanticMethodReview,
    file_context: &str,
    stale_signature_proof: Option<&StaleDiscardSignatureProof>,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(SemanticMethodReview, usize, usize), String> {
    let discard_block = super::super::dossier::python_parameter_discard_block(method);
    if let (Some(discard_block), Some(proof)) = (&discard_block, stale_signature_proof) {
        return adjudicate_typed_stale_signature(
            analyzer,
            method,
            &review,
            file_context,
            discard_block,
            proof,
            on_progress,
        )
        .await;
    }
    if matches!(review.tier, FindingTier::Slop | FindingTier::KindaSlop) {
        return Ok((review, 0, 0));
    }
    let Some(discard_block) = discard_block else {
        return Ok((review, 0, 0));
    };
    if let Some(callback) = on_progress {
        callback(ReviewProgress::RetryingEvidence {
            label: format!(
                "scoped construct: method {}::{}",
                method.file_path, method.name
            ),
        });
    }
    let prompt = format!(
        "You are judging the cognitive friction of one structurally proven behavior-neutral Python parameter-discard block. Sniff has established that the block only reads local parameter identifiers and has no calls, indexing, attribute access, mutation, or side effects. Deleting only this block leaves the callable signature, return value, exceptions, side effects, callers, callbacks, protocols, and compatibility behavior unchanged. Do not judge or propose changing the accepted parameters; that is a separate claim requiring typed closed-world proof. Return `kinda_slop` when the no-op acknowledgment is unnecessary ceremony that makes a human inspect behavior with no semantic effect. Return `clean` only when the dossier establishes that retaining the explicit acknowledgment communicates a concrete repository contract. Return `unresolved` only when its cognitive severity cannot be assessed. Never return `slop`: this local construct is minor by definition.\n\nFile: {}\nMethod: {}\nEvidence line range: absolute file line numbers from {} through {}\n\nContaining-file and repository dossier:\n---\n{}\n---\n\nMethod source:\n---\n{}\n---\n\nStructurally verified parameter-discard block:\n---\n{}\n---\n\nReturn exactly one JSON object: {{\"tier\":\"kinda_slop | clean | unresolved\",\"reason\":\"one precise sentence about cognitive friction\"}}",
        method.file_path,
        method.name,
        method.start_line,
        method.end_line,
        file_context,
        numbered_method_source(method),
        discard_block,
    );
    let (result, input_tokens, output_tokens) = analyzer
        .llm_client
        .call_single(&prompt, ResponseSchema::ScopedTierReview)
        .await?;
    let Some(result) = result else {
        return Ok((
            unresolved_construct_adjudication(
                &review,
                "AI did not classify the proven local parameter-discard ceremony.",
            ),
            input_tokens,
            output_tokens,
        ));
    };
    let reason = result
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("The AI severity judgment did not include a usable reason.")
        .to_string();
    let resolved = match result.get("tier").and_then(serde_json::Value::as_str) {
        Some("kinda_slop") => {
            proven_local_parameter_discard_review(method, &review, &discard_block, reason)
        }
        Some("clean") => review,
        _ => unresolved_construct_adjudication(
            &review,
            "AI could not classify the proven local parameter-discard ceremony.",
        ),
    };
    Ok((resolved, input_tokens, output_tokens))
}

fn proven_local_parameter_discard_review(
    method: &MethodRecord,
    review: &SemanticMethodReview,
    discard_block: &str,
    reason: String,
) -> SemanticMethodReview {
    SemanticMethodReview {
        tier: FindingTier::KindaSlop,
        pattern: crate::product_contract::SlopPattern::CeremonialLogic,
        intent: review.intent.clone(),
        reason,
        evidence: vec![construct_evidence(method, discard_block)],
        necessity_check:
            "Python does not require accepted unused parameters to be read inside the method."
                .to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact:
            "Deleting only the no-op block leaves the callable signature and behavior unchanged."
                .to_string(),
        dependency_impact:
            "Callers, callbacks, protocols, tests, and compatibility consumers observe no change."
                .to_string(),
        simplification: "Delete only the no-op parameter-discard block.".to_string(),
        change_scope: "local".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    }
}

async fn adjudicate_typed_stale_signature(
    analyzer: &Analyzer,
    method: &MethodRecord,
    review: &SemanticMethodReview,
    file_context: &str,
    discard_block: &str,
    proof: &StaleDiscardSignatureProof,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(SemanticMethodReview, usize, usize), String> {
    if let Some(callback) = on_progress {
        callback(ReviewProgress::RetryingEvidence {
            label: format!(
                "typed stale-signature severity: method {}::{}",
                method.file_path, method.name
            ),
        });
    }
    let prompt = format!(
        "You are judging the severity of proven unnecessary conceptual machinery. Sniff has already established, from a closed repository graph, that this private Python signature carries discarded parameters with no contract role and that removing their side-effect-free caller arguments preserves behavior. Do not re-litigate whether the method has a caller; judge only the cognitive friction of retaining the proven stale signature and discard ceremony. Return `slop` when it meaningfully obscures the real contract, `kinda_slop` when the friction is minor/local, `clean` only if the supplied proof itself establishes no unnecessary machinery, or `unresolved` only if severity cannot be assessed.\n\nFile: {}\nMethod: {}\nTyped proof: {}\n\nComplete dossier:\n---\n{}\n---\n\nMethod source:\n---\n{}\n---\n\nReturn exactly one JSON object: {{\"tier\":\"slop | kinda_slop | clean | unresolved\",\"reason\":\"one precise sentence about cognitive friction\"}}",
        method.file_path,
        method.name,
        proof.render(),
        file_context,
        numbered_method_source(method),
    );
    let (result, input_tokens, output_tokens) = analyzer
        .llm_client
        .call_single(&prompt, ResponseSchema::ScopedTierReview)
        .await?;
    let Some(result) = result else {
        return Ok((
            unresolved_stale_signature_adjudication(review, proof),
            input_tokens,
            output_tokens,
        ));
    };
    let reason = result
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("The AI severity judgment did not include a usable reason.")
        .to_string();
    let tier = match result.get("tier").and_then(serde_json::Value::as_str) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        _ => {
            return Ok((
                unresolved_stale_signature_adjudication(review, proof),
                input_tokens,
                output_tokens,
            ));
        }
    };
    Ok((
        proven_stale_signature_review(method, review, proof, discard_block, tier, reason),
        input_tokens,
        output_tokens,
    ))
}

fn proven_stale_signature_review(
    method: &MethodRecord,
    review: &SemanticMethodReview,
    proof: &StaleDiscardSignatureProof,
    discard_block: &str,
    tier: FindingTier,
    reason: String,
) -> SemanticMethodReview {
    let lines = method.source.lines().collect::<Vec<_>>();
    let signature_end = lines
        .iter()
        .position(|line| line.trim_end().ends_with(':'))
        .unwrap_or(0);
    let block_lines = discard_block.lines().collect::<Vec<_>>();
    let block_start = lines
        .windows(block_lines.len())
        .position(|window| window == block_lines)
        .unwrap_or(0);
    let parameters = proof.discarded_parameters.join(", ");
    SemanticMethodReview {
        tier,
        pattern: crate::product_contract::SlopPattern::CeremonialLogic,
        intent: review.intent.clone(),
        reason,
        evidence: vec![
            SemanticEvidence {
                start_line: method.start_line,
                end_line: method.start_line + signature_end,
                quote: lines[..=signature_end].join("\n"),
            },
            SemanticEvidence {
                start_line: method.start_line + block_start,
                end_line: method.start_line + block_start + block_lines.len().saturating_sub(1),
                quote: discard_block.to_string(),
            },
        ],
        necessity_check: format!(
            "The typed dossier proves {parameters} have no reads outside the pure discard block."
        ),
        contract_status: "unnecessary".to_string(),
        contract_impact:
            "The private callable and its closed callers retain identical observable behavior."
                .to_string(),
        dependency_impact:
            "Every resolved caller can remove only the proven side-effect-free arguments."
                .to_string(),
        simplification: format!(
            "Remove parameters {parameters}, their closed-caller arguments, and the discard block."
        ),
        change_scope: "signature".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    }
}

fn unresolved_stale_signature_adjudication(
    review: &SemanticMethodReview,
    proof: &StaleDiscardSignatureProof,
) -> SemanticMethodReview {
    SemanticMethodReview {
        tier: FindingTier::Unresolved,
        pattern: crate::product_contract::SlopPattern::None,
        intent: review.intent.clone(),
        reason: "AI adjudication did not resolve the established stale discarded-parameter proof."
            .to_string(),
        evidence: Vec::new(),
        necessity_check: "The typed dossier proves the parameters unused, but AI did not classify the resulting machinery."
            .to_string(),
        contract_status: "unknown".to_string(),
        contract_impact: "The AI verdict conflicts with the closed-world signature evidence."
            .to_string(),
        dependency_impact: "No dependency was established, but the AI classification remained invalid."
            .to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "unknown".to_string(),
        missing_evidence: vec![format!(
            "valid AI adjudication of typed proof: {}",
            proof.render()
        )],
    }
}
