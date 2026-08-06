use crate::product_contract::SlopPattern;
use crate::report_types::LLMVerdict;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SemanticEvidence {
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
    pub(crate) quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SemanticMethodReview {
    pub(crate) tier: FindingTier,
    pub(crate) pattern: SlopPattern,
    pub(crate) intent: String,
    pub(crate) reason: String,
    pub(crate) evidence: Vec<SemanticEvidence>,
    pub(crate) necessity_check: String,
    pub(crate) contract_status: String,
    pub(crate) contract_impact: String,
    pub(crate) dependency_impact: String,
    pub(crate) simplification: String,
    pub(crate) change_scope: String,
    pub(crate) behavior_status: String,
    pub(crate) missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IntentMethodReview {
    pub(crate) intent: String,
    pub(crate) contract_status: String,
    pub(crate) necessity_check: String,
    pub(crate) missing_evidence: Vec<String>,
}

pub(crate) fn parse_intent_method_review(
    result: &serde_json::Value,
) -> Result<IntentMethodReview, String> {
    let string_field = |name: &str| {
        result
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("intent review is missing non-empty {name}"))
    };
    let missing_evidence = result
        .get("missing_evidence")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "intent review is missing missing_evidence array".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    "intent missing_evidence entry is not a non-empty string".to_string()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let contract_status = string_field("contract_status")?;
    if !matches!(
        contract_status.as_str(),
        "required" | "unnecessary" | "unknown"
    ) {
        return Err(format!(
            "intent review has invalid contract_status: {contract_status}"
        ));
    }
    Ok(IntentMethodReview {
        intent: string_field("intent")?,
        contract_status,
        necessity_check: string_field("necessity_check")?,
        missing_evidence,
    })
}

pub(crate) fn parse_result_fields(
    result: &serde_json::Value,
) -> (FindingTier, String, String, Option<bool>, Option<bool>) {
    let tier = match result.get("tier").and_then(|v| v.as_str()) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        Some("clean") => FindingTier::Clean,
        Some("unresolved") => FindingTier::Unresolved,
        _ => FindingTier::Unresolved,
    };
    let evidence = result
        .get("evidence")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let reason = result
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let cohesive = result.get("cohesive").and_then(|v| v.as_bool());
    let name_accurate = result.get("name_accurate").and_then(|v| v.as_bool());
    (tier, evidence, reason, cohesive, name_accurate)
}

pub(crate) fn validate_file_review(result: &serde_json::Value) -> Result<(), String> {
    let smelly = result
        .get("smelly")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| "file verdict is missing boolean smelly".to_string())?;
    let tier = result
        .get("tier")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "file verdict is missing string tier".to_string())?;
    let tier_is_smelly = match tier {
        "slop" | "kinda_slop" => true,
        "clean" | "unresolved" => false,
        other => return Err(format!("invalid file verdict tier: {other}")),
    };
    if smelly != tier_is_smelly {
        return Err("file verdict smelly and tier disagree".to_string());
    }

    if !result
        .get("evidence")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err("file verdict is missing string evidence".to_string());
    }
    Ok(())
}

pub(crate) fn parse_semantic_method_review(
    result: &serde_json::Value,
    source: &str,
    method_start_line: usize,
    method_end_line: usize,
) -> Result<SemanticMethodReview, String> {
    let tier = match result.get("tier").and_then(|value| value.as_str()) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        Some("clean") => FindingTier::Clean,
        Some("unresolved") => FindingTier::Unresolved,
        Some(other) => return Err(format!("invalid semantic tier: {other}")),
        None => return Err("semantic verdict is missing tier".to_string()),
    };
    let string_field = |name: &str| {
        result
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("semantic verdict is missing non-empty {name}"))
    };
    let raw_pattern = string_field("pattern")?;
    let pattern = SlopPattern::parse(&raw_pattern)
        .ok_or_else(|| format!("unknown semantic slop pattern: {raw_pattern}"))?;
    let intent = string_field("intent")?;
    let reason = result
        .get("reason")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let necessity_check = string_field("necessity_check")?;
    let contract_status = string_field("contract_status")?;
    let contract_impact = string_field("contract_impact")?;
    let dependency_impact = string_field("dependency_impact")?;
    let simplification = result
        .get("simplification")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let change_scope = string_field("change_scope")?;
    let raw_behavior_status = string_field("behavior_status")?;
    let behavior_status = match (tier, raw_behavior_status.as_str()) {
        (_, "preserved" | "unknown") => raw_behavior_status,
        // Some providers describe an unchanged Clean method as "known".
        // This is not sufficient proof for a behavior-neutral simplification.
        (FindingTier::Clean, "known") => "preserved".to_string(),
        _ => {
            return Err(format!(
                "semantic verdict has invalid behavior_status: {raw_behavior_status}"
            ));
        }
    };
    if !matches!(
        contract_status.as_str(),
        "required" | "unnecessary" | "unknown"
    ) {
        return Err(format!(
            "semantic verdict has invalid contract_status: {contract_status}"
        ));
    }
    let missing_evidence = result
        .get("missing_evidence")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "semantic verdict is missing missing_evidence array".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    "semantic missing_evidence entry is not a non-empty string".to_string()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proof_contains_uncertainty = [&necessity_check, &contract_impact, &dependency_impact]
        .iter()
        .any(|value| states_unresolved_evidence(value));

    if matches!(tier, FindingTier::Clean) {
        if pattern != SlopPattern::None {
            return Err("clean semantic verdict must use pattern `none`".to_string());
        }
        if contract_status != "required"
            || behavior_status != "preserved"
            || change_scope != "none"
            || simplification != "none"
            || !missing_evidence.is_empty()
            || proof_contains_uncertainty
        {
            return Err(
                "clean semantic verdict must prove a required contract, preserved behavior, no simplification, and no unresolved evidence"
                    .to_string(),
            );
        }
    } else if matches!(tier, FindingTier::Unresolved) {
        if pattern != SlopPattern::None {
            return Err("unresolved semantic verdict must use pattern `none`".to_string());
        }
        if missing_evidence.is_empty()
            || contract_status != "unknown"
            || behavior_status != "unknown"
            || simplification != "none"
            || change_scope != "none"
            || reason.is_empty()
        {
            return Err("unresolved semantic verdict must use an unknown contract and behavior, no simplification, no change scope, and list missing evidence".to_string());
        }
    } else if !pattern.is_finding() {
        return Err("non-clean semantic verdict must use a finding pattern".to_string());
    }
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
        && !matches!(
            change_scope.as_str(),
            "local" | "signature" | "whole_method"
        )
    {
        return Err(format!(
            "non-clean semantic verdict has invalid change_scope: {change_scope}"
        ));
    }
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
        && change_scope == "whole_method"
        && !describes_callable_deletion(&simplification)
    {
        return Err(
            "whole_method change_scope is valid only when the simplification deletes the callable"
                .to_string(),
        );
    }
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
        && change_scope == "local"
        && describes_signature_change(&simplification)
    {
        return Err(
            "local change_scope cannot propose removing parameters or changing the callable signature"
                .to_string(),
        );
    }
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
        && change_scope == "signature"
        && !describes_signature_change(&simplification)
    {
        return Err(
            "signature change_scope must describe the exact parameter or callable-signature change"
                .to_string(),
        );
    }
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop) {
        if contract_status != "unnecessary" {
            return Err(
                "non-clean semantic verdict must prove an unnecessary contract".to_string(),
            );
        }
        if behavior_status != "preserved" {
            return Err("non-clean semantic verdict must prove behavior is preserved".to_string());
        }
        if !missing_evidence.is_empty() {
            return Err(
                "non-clean semantic verdict cannot retain unresolved missing evidence".to_string(),
            );
        }
        if proof_contains_uncertainty {
            return Err(
                "non-clean semantic verdict cannot contain uncertain contract or dependency proof"
                    .to_string(),
            );
        }
        if reason.is_empty()
            || simplification.is_empty()
            || proof_is_placeholder(&necessity_check)
            || proof_is_placeholder(&contract_impact)
            || proof_is_placeholder(&dependency_impact)
            || proof_is_placeholder(&simplification)
        {
            return Err("non-clean semantic verdict must provide substantive necessity, contract, dependency, and simplification proof".to_string());
        }
    }
    let entries = match result.get("evidence").and_then(|value| value.as_array()) {
        Some(entries) => entries.as_slice(),
        None if matches!(tier, FindingTier::Clean | FindingTier::Unresolved) => &[],
        None => return Err("semantic verdict is missing evidence array".to_string()),
    };
    if matches!(tier, FindingTier::Clean) {
        // Models sometimes include explanatory evidence even after choosing
        // clean. It cannot become a finding, so discard it rather than
        // turning an otherwise valid review into a scan failure.
        return Ok(SemanticMethodReview {
            tier,
            pattern,
            intent,
            reason,
            evidence: Vec::new(),
            necessity_check,
            contract_status,
            contract_impact,
            dependency_impact,
            simplification,
            change_scope,
            behavior_status,
            missing_evidence,
        });
    }

    let source_lines = source.lines().collect::<Vec<_>>();
    let mut evidence = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| "semantic evidence entry is not an object".to_string())?;
        let start_line = object
            .get("start_line")
            .and_then(|value| value.as_u64())
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| "semantic evidence has invalid start_line".to_string())?;
        let end_line = object
            .get("end_line")
            .and_then(|value| value.as_u64())
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| "semantic evidence has invalid end_line".to_string())?;
        let quote = object
            .get("quote")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| "semantic evidence has an empty quote".to_string())?;

        let (start_line, end_line) = canonical_evidence_range(
            source,
            &source_lines,
            method_start_line,
            method_end_line,
            start_line,
            end_line,
            &quote,
        )?;
        evidence.push(SemanticEvidence {
            start_line,
            end_line,
            quote,
        });
    }

    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop) && evidence.is_empty() {
        return Err("non-clean semantic verdict must include evidence".to_string());
    }
    Ok(SemanticMethodReview {
        tier,
        pattern,
        intent,
        reason,
        evidence,
        necessity_check,
        contract_status,
        contract_impact,
        dependency_impact,
        simplification,
        change_scope,
        behavior_status,
        missing_evidence,
    })
}

pub(crate) fn parse_adversarial_method_review(
    result: &serde_json::Value,
    intent: &IntentMethodReview,
    source: &str,
    method_start_line: usize,
    method_end_line: usize,
) -> Result<SemanticMethodReview, String> {
    let tier = match result.get("tier").and_then(|value| value.as_str()) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        Some("clean") => FindingTier::Clean,
        Some("unresolved") => FindingTier::Unresolved,
        Some(other) => return Err(format!("invalid adversarial tier: {other}")),
        None => return Err("adversarial verdict is missing tier".to_string()),
    };
    if matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
        || result.get("contract_impact").is_some()
        || result.get("dependency_impact").is_some()
        || result.get("simplification").is_some()
        || result.get("change_scope").is_some()
        || result.get("behavior_status").is_some()
    {
        return parse_semantic_method_review(result, source, method_start_line, method_end_line);
    }

    let reason = result
        .get("reason")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "compact adversarial verdict is missing non-empty reason".to_string())?;
    if result
        .get("pattern")
        .and_then(|value| value.as_str())
        .is_some_and(|pattern| pattern != "none")
    {
        return Err("compact clean or unresolved verdict must use pattern `none`".to_string());
    }
    if result
        .get("evidence")
        .is_some_and(|value| !value.as_array().is_some_and(Vec::is_empty))
    {
        return Err("compact clean or unresolved verdict cannot include evidence".to_string());
    }
    let missing_evidence = result
        .get("missing_evidence")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "compact missing_evidence must be an array".to_string())?
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .map(str::trim)
                        .filter(|entry| !entry.is_empty())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            "compact missing_evidence entry must be a non-empty string".to_string()
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    match tier {
        FindingTier::Clean => {
            if !missing_evidence.is_empty() {
                return Err("compact clean verdict cannot list missing evidence".to_string());
            }
            let contract_established =
                intent.contract_status == "required" && intent.missing_evidence.is_empty();
            Ok(SemanticMethodReview {
                tier,
                pattern: SlopPattern::None,
                intent: intent.intent.clone(),
                reason,
                evidence: Vec::new(),
                necessity_check: intent.necessity_check.clone(),
                contract_status: if contract_established {
                    "required".to_string()
                } else {
                    "unknown".to_string()
                },
                contract_impact: if contract_established {
                    "The intent investigation established a required callable contract.".to_string()
                } else {
                    "The callable contract remains unknown pending adjudication.".to_string()
                },
                dependency_impact: if contract_established {
                    "The repository dossier supports the established method dependency.".to_string()
                } else {
                    "Dependency impact remains unknown pending adjudication.".to_string()
                },
                simplification: "none".to_string(),
                change_scope: "none".to_string(),
                behavior_status: "preserved".to_string(),
                missing_evidence,
            })
        }
        FindingTier::Unresolved => {
            if missing_evidence.is_empty() {
                return Err("compact unresolved verdict must list missing evidence".to_string());
            }
            Ok(SemanticMethodReview {
                tier,
                pattern: SlopPattern::None,
                intent: intent.intent.clone(),
                reason,
                evidence: Vec::new(),
                necessity_check: intent.necessity_check.clone(),
                contract_status: "unknown".to_string(),
                contract_impact: "The contract impact remains unknown.".to_string(),
                dependency_impact: "The dependency impact remains unknown.".to_string(),
                simplification: "none".to_string(),
                change_scope: "none".to_string(),
                behavior_status: "unknown".to_string(),
                missing_evidence,
            })
        }
        FindingTier::Slop | FindingTier::KindaSlop => unreachable!(),
    }
}

fn states_unresolved_evidence(value: &str) -> bool {
    let normalized = value.to_lowercase();
    [
        "cannot establish",
        "cannot be established",
        "could not establish",
        "unable to establish",
        "cannot determine",
        "cannot be determined",
        "could not determine",
        "unable to determine",
        "insufficient evidence",
        "missing evidence",
        "not enough evidence",
        "evidence is incomplete",
        "evidence remains incomplete",
        "usage is not fully visible",
        "contract is unknown",
        "contract remains unknown",
        "callers are unknown",
        "dependencies are unknown",
        "unclear whether",
        "uncertain whether",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase))
}

fn proof_is_placeholder(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_end_matches(['.', ';', ':'])
        .to_ascii_lowercase();
    normalized.split_whitespace().count() < 3
        || matches!(
            normalized.as_str(),
            "none" | "n/a" | "na" | "not applicable" | "no impact" | "unchanged" | "required"
        )
}

fn describes_callable_deletion(value: &str) -> bool {
    let normalized = value.to_lowercase();
    ["delete", "remove", "drop"]
        .iter()
        .any(|verb| normalized.contains(verb))
        && ["method", "function", "callable", "helper", "wrapper"]
            .iter()
            .any(|noun| normalized.contains(noun))
}

fn describes_signature_change(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("signature")
        || (["remove", "delete", "drop"]
            .iter()
            .any(|verb| normalized.contains(verb))
            && ["parameter", "parameters", "argument", "arguments"]
                .iter()
                .any(|noun| normalized.contains(noun)))
}

fn canonical_evidence_range(
    source: &str,
    source_lines: &[&str],
    method_start_line: usize,
    method_end_line: usize,
    declared_start_line: usize,
    declared_end_line: usize,
    quote: &str,
) -> Result<(usize, usize), String> {
    if declared_start_line >= method_start_line
        && declared_end_line >= declared_start_line
        && declared_end_line <= method_end_line
    {
        let relative_start = declared_start_line - method_start_line;
        let relative_end = declared_end_line - method_start_line;
        if relative_end < source_lines.len() {
            let span_source = source_lines[relative_start..=relative_end].join("\n");
            if evidence_matches_source(&span_source, quote) {
                return Ok((declared_start_line, declared_end_line));
            }
        }
    }

    let locations = source
        .match_indices(quote)
        .filter_map(|(offset, _)| {
            let start_line =
                method_start_line + source[..offset].bytes().filter(|b| *b == b'\n').count();
            let end_line = start_line + quote.bytes().filter(|b| *b == b'\n').count();
            (start_line >= method_start_line && end_line <= method_end_line)
                .then_some((start_line, end_line))
        })
        .collect::<Vec<_>>();

    if let [location] = locations.as_slice() {
        return Ok(*location);
    }
    if locations.len() > 1 {
        return Err(format!(
            "semantic evidence quote is ambiguous and does not identify one source span: lines {declared_start_line}-{declared_end_line}"
        ));
    }

    let normalized_locations =
        normalized_evidence_locations(source, method_start_line, method_end_line, quote);
    match normalized_locations.as_slice() {
        [location] => Ok(*location),
        [] => Err(format!(
            "semantic evidence quote does not belong to its declared line range: lines {declared_start_line}-{declared_end_line}"
        )),
        _ => Err(format!(
            "semantic evidence quote is ambiguous and does not identify one source span: lines {declared_start_line}-{declared_end_line}"
        )),
    }
}

fn normalized_evidence_locations(
    source: &str,
    method_start_line: usize,
    method_end_line: usize,
    quote: &str,
) -> Vec<(usize, usize)> {
    let source_chars = source
        .lines()
        .enumerate()
        .flat_map(|(line_offset, line)| {
            line.chars()
                .filter(|character| !character.is_whitespace())
                .map(move |character| (character, method_start_line + line_offset))
        })
        .collect::<Vec<_>>();
    let quote_chars = quote
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<Vec<_>>();
    if quote_chars.is_empty() {
        return Vec::new();
    }

    source_chars
        .windows(quote_chars.len())
        .filter_map(|window| {
            window
                .iter()
                .map(|(character, _)| *character)
                .eq(quote_chars.iter().copied())
                .then(|| {
                    let start_line = window.first().map(|(_, line)| *line)?;
                    let end_line = window.last().map(|(_, line)| *line)?;
                    (start_line >= method_start_line && end_line <= method_end_line)
                        .then_some((start_line, end_line))
                })
                .flatten()
        })
        .collect()
}

pub(crate) fn build_semantic_method_verdict(
    review: &SemanticMethodReview,
    file_path: &str,
    method_name: &str,
    loc: usize,
    start_line: usize,
    end_line: usize,
) -> LLMVerdict {
    let reason = if matches!(review.tier, FindingTier::Clean) {
        review.reason.clone()
    } else if matches!(review.tier, FindingTier::Unresolved) {
        format!(
            "{} Missing evidence: {}",
            review.reason,
            review.missing_evidence.join("; ")
        )
    } else {
        format!(
            "{}: {} Simplification: {} Contract impact: {} Dependency proof: {} Necessity proof: {}",
            review.pattern.label(),
            review.reason,
            review.simplification,
            review.contract_impact,
            review.dependency_impact,
            review.necessity_check,
        )
    };
    let evidence = review
        .evidence
        .iter()
        .map(|entry| entry.quote.as_str())
        .collect::<Vec<_>>()
        .join("\n---\n");
    LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: file_path.to_string(),
        method_name: Some(method_name.to_string()),
        check_type: "method".to_string(),
        smelly: matches!(review.tier, FindingTier::Slop | FindingTier::KindaSlop),
        tier: review.tier,
        cohesive: None,
        name_accurate: None,
        evidence,
        reason,
        loc,
        start_line,
        end_line,
    }
}

pub(crate) fn build_file_verdict(result: &serde_json::Value, file_path: &str) -> LLMVerdict {
    let (tier, evidence, reason, cohesive, name_accurate) = parse_result_fields(result);
    LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file_path.to_string(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: matches!(tier, FindingTier::Slop | FindingTier::KindaSlop),
        tier,
        cohesive,
        name_accurate,
        evidence,
        reason,
        loc: 0,
        start_line: 0,
        end_line: 0,
    }
}

pub(crate) fn evidence_matches_source(source: &str, evidence: &str) -> bool {
    let trimmed = evidence.trim();
    if trimmed.is_empty() {
        return false;
    }

    if source.contains(trimmed) {
        return true;
    }

    fn strip_whitespace(text: &str) -> String {
        text.chars().filter(|ch| !ch.is_whitespace()).collect()
    }

    let normalized_source = strip_whitespace(source);
    let normalized_evidence = strip_whitespace(trimmed);
    !normalized_evidence.is_empty() && normalized_source.contains(&normalized_evidence)
}

#[cfg(test)]
#[path = "tests/analyzer_result.rs"]
mod tests;
