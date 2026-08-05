use super::*;

pub(super) fn render_repository_facts(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> RepositoryFacts {
    let graph = index.graph;
    let file_records = index.file_records;
    let method_name = &method.name;
    let private_js_ts_package = js_ts_file_is_in_private_package(method, index);
    let repository_external_visibility = has_repository_external_visibility(method, index);
    let file_role = classify_file_role(&file.file_path);
    let method_test_runner_contract = index
        .test_runner_methods
        .contains(&(file.file_path.to_lowercase(), method.start_line));
    let role_based_consumer =
        method_test_runner_contract || method_role_consumer(file_role, method);
    let target_definition_id = graph.files.get(&file.file_path).and_then(|symbols| {
        symbols
            .definitions
            .iter()
            .find(|definition| {
                definition.name == *method_name
                    && definition.start_line <= method.start_line
                    && method.end_line <= definition.end_line
            })
            .map(|definition| definition.id)
    });
    let mut facts = Vec::new();
    if method.language == "go" && repository_external_visibility && method.real_ref_count == 0 {
        facts.push(
            "external callable boundary: established by the exported/public declaration; absent in-repository callers are expected and are not missing contract evidence"
                .to_string(),
        );
    }
    let resolved_sites = method
        .references
        .iter()
        .map(|reference| (reference.file_path.to_lowercase(), reference.line))
        .collect::<HashSet<_>>();
    let differently_resolved_sites = index
        .resolved_sites_by_leaf
        .get(method_name)
        .into_iter()
        .flatten()
        .filter(|site| !resolved_sites.contains(*site))
        .cloned()
        .collect::<HashSet<_>>();
    let unresolved_symbol_sites = index
        .unresolved_sites_by_leaf
        .get(method_name)
        .cloned()
        .unwrap_or_default();

    let target_owner = graph
        .files
        .get(&file.file_path)
        .and_then(|symbols| {
            symbols.definitions.iter().find(|definition| {
                matches!(&definition.kind, crate::types::SymbolKind::Method)
                    && definition.name == *method_name
                    && definition.start_line <= method.start_line
                    && method.end_line <= definition.end_line
            })
        })
        .and_then(|definition| definition.owner_type.as_deref());
    let (go_owner_constructions, go_interface_guards) = target_owner
        .filter(|_| method.language == "go" && method.is_exported)
        .map(|owner| go_owner_contract_evidence(owner, index))
        .unwrap_or_default();
    if !go_interface_guards.is_empty() {
        facts.push(format!(
            "Go owner construction evidence: {}",
            if_empty(go_owner_constructions.clone())
        ));
        facts.push(format!(
            "Go compile-time interface guards: {}",
            if_empty(go_interface_guards.clone())
        ));
    }
    let object_owner = target_owner.and_then(|owner| {
        graph
            .files
            .get(&file.file_path)?
            .definitions
            .iter()
            .find(|definition| {
                matches!(definition.kind, crate::types::SymbolKind::Variable)
                    && definition.name == owner
            })
    });
    let object_owner_usage = object_owner
        .map(|owner| {
            index
                .source_locations(&owner.name)
                .into_iter()
                .filter_map(|location| {
                    let candidate = &file_records[location.file_index];
                    let line_number = location.line_index + 1;
                    if candidate.file_path != file.file_path
                        || (owner.start_line..=owner.end_line).contains(&line_number)
                    {
                        return None;
                    }
                    Some(format!(
                        "{}:{}: {}",
                        candidate.file_path,
                        line_number,
                        index.source_lines[location.file_index][location.line_index].trim()
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let inline_object_owner = target_owner.filter(|owner| owner.starts_with("<object@"));
    let class_contract = target_owner.and_then(|owner| class_contract_evidence(file, owner));
    let owner_invocation_evidence = js_ts_owner_invocation_evidence(method, target_owner, index);
    let dynamic_import_evidence = dynamic_import_evidence(method, index);
    let commonjs_require_evidence = commonjs_require_evidence(method, index);
    let private_surface_declarations =
        private_js_ts_surface_declaration_evidence(file, method, index);
    let returned_surface_entries = returned_member_surface_entries(file, method);
    let external_framework_contract = external_framework_contract_evidence(file, method, index);
    let external_object_escape =
        object_owner.and_then(|owner| external_object_escape_evidence(file, &owner.name, index));
    let returned_member_evidence = externally_returned_member_evidence(file, method);
    let mut returned_member_usage = returned_member_usage_evidence(file, method, index);
    if let Some(owner) = target_owner {
        returned_member_usage.extend(factory_constructed_class_member_usage_evidence(
            file, method, owner, index,
        ));
    }
    if let Some(owner) = inline_object_owner {
        returned_member_usage.extend(inline_object_surface_usage_evidence(
            file, owner, method, index,
        ));
        returned_member_usage.sort();
        returned_member_usage.dedup();
    }
    let allow_unknown_js_ts_member = false;
    let inline_object_argument_contract = inline_object_owner.is_some_and(|owner| {
        returned_member_evidence.is_none() && !inline_object_is_implicit_return(file, owner)
    });
    let enumeration_evidence = object_owner
        .map(|owner| object_enumeration_evidence(&owner.name, index))
        .unwrap_or_default();
    let enumeration_invocation_proof = object_owner
        .and_then(|owner| object_enumeration_invocation_proof(&owner.name, &enumeration_evidence));
    let computed_invocation_evidence = object_owner
        .map(|owner| object_computed_invocation_evidence(&owner.name, index))
        .unwrap_or_default();
    let unowned_nested_callable = target_owner.is_none()
        && returned_surface_entries.is_empty()
        && file.methods.iter().any(|candidate| {
            candidate.start_line < method.start_line && method.end_line <= candidate.end_line
        });
    let owner_has_repository_external_visibility =
        object_owner.is_some_and(|owner| owner.is_exported && !private_js_ts_package);
    if let Some(owner) = object_owner {
        facts.push(format!(
            "object-member invocation contract: member of {} object `{}`; member dispatch occurs through the object boundary",
            if owner.is_exported {
                "exported"
            } else {
                "repository"
            },
            owner.name
        ));
        facts.push(format!(
            "owning object repository consumers: {}",
            if_empty(object_owner_usage.clone())
        ));
    } else if let Some(owner) = inline_object_owner {
        facts.push(format!(
            "object-member invocation contract: callback/property belongs to inline object `{owner}` and is consumed through its containing expression"
        ));
    }
    if object_owner.is_some() {
        facts.push(format!(
            "dynamic object enumeration evidence: {}",
            if_empty(enumeration_evidence.clone())
        ));
        facts.push(format!(
            "computed object-member invocation evidence: {}",
            if_empty(computed_invocation_evidence.clone())
        ));
    }
    if let Some(proof) = enumeration_invocation_proof.as_deref() {
        facts.push(format!("enumerated-member invocation proof: {proof}"));
    }
    if private_js_ts_package
        && (method.is_exported || target_owner.is_some() || returned_member_evidence.is_some())
    {
        facts.push("private JavaScript/TypeScript package boundary: true".to_string());
    }
    if unowned_nested_callable {
        facts.push(
            "nested callable has no resolved owner; closed-world dispatch proof is unavailable"
                .to_string(),
        );
    }
    if let Some(contract) = class_contract.as_deref() {
        facts.push(contract.to_string());
    }
    facts.push(format!(
        "owner-qualified construction/invocation evidence: {}",
        if_empty(owner_invocation_evidence.clone())
    ));
    facts.push(format!(
        "path-resolved dynamic-import evidence: {}",
        if_empty(dynamic_import_evidence.clone())
    ));
    facts.push(format!(
        "path-resolved CommonJS import evidence: {}",
        if_empty(commonjs_require_evidence.clone())
    ));
    facts.push(format!(
        "matching private type/interface surface declarations requiring coordinated removal: {}",
        if_empty(private_surface_declarations.clone())
    ));
    if !returned_surface_entries.is_empty() {
        facts.push(format!(
            "private returned-object surface entries requiring coordinated removal: {}",
            returned_surface_entries
                .iter()
                .map(|(line, source)| format!("{}:{line}: {source}", file.file_path))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if let Some(contract) = external_framework_contract.as_deref() {
        facts.push(format!(
            "external framework configuration evidence: {contract}"
        ));
    }
    if let Some(contract) = external_object_escape.as_deref() {
        facts.push(format!("external object-protocol evidence: {contract}"));
    }
    let implementations = index
        .definitions_by_name
        .get(method_name)
        .into_iter()
        .flatten()
        .filter_map(|location| {
            let definition = graph
                .files
                .get(&location.path)?
                .definitions
                .get(location.index)?;
            (matches!(&definition.kind, crate::types::SymbolKind::Method)
                && !(location.path == file.file_path && definition.start_line == method.start_line)
                && target_owner
                    .zip(definition.owner_type.as_deref())
                    .is_some_and(|(target, candidate)| {
                        owners_share_contract(graph, target, candidate)
                    }))
            .then(|| {
                format!(
                    "{} lines {}-{} owner={}",
                    location.path,
                    definition.start_line,
                    definition.end_line,
                    definition.owner_type.as_deref().unwrap_or("none")
                )
            })
        })
        .collect::<Vec<_>>();
    let has_parallel_implementation = !implementations.is_empty();
    facts.push(format!(
        "same-name implementations/overrides: {}",
        if_empty(implementations)
    ));
    if role_based_consumer {
        facts.push(format!(
            "method-level role consumer: {}",
            if method_test_runner_contract {
                "Rust test method invoked by the test runner"
            } else {
                role_contract_evidence(file_role)
            }
        ));
    }

    let mut test_usage = Vec::new();
    let file_test_contract = if has_external_visibility(method) {
        file_test_contract_evidence(file, index)
    } else {
        Vec::new()
    };
    let file_content_test_contract = file_content_test_contract_evidence(file, method, index);
    let mut seam_usage = Vec::new();
    let mut callback_usage = Vec::new();
    let mut compatibility_usage = Vec::new();
    let mut protocol_usage = Vec::new();
    let mut non_call_usage = Vec::new();
    let mut lexical_call_sites = Vec::new();
    let mut lexical_call_locations = Vec::new();
    for location in index.source_locations(method_name) {
        let candidate = &file_records[location.file_index];
        let candidate_lower = candidate.file_path.to_lowercase();
        let line_index = location.line_index;
        let line = index.source_lines[location.file_index][line_index];
        let semantic_context = context_without_target_identifier(line, method_name);
        let evidence = format!(
            "{}:{}: {}",
            candidate.file_path,
            line_index + 1,
            line.trim()
        );
        let evidence_window = index.source_window(location);
        let is_definition = candidate.methods.iter().any(|candidate_method| {
            candidate_method.name == *method_name && candidate_method.start_line == line_index + 1
        });
        let is_target_definition =
            candidate.file_path == file.file_path && line_index + 1 == method.start_line;
        let site = (candidate_lower.clone(), line_index + 1);
        let has_graph_record = graph.files.contains_key(&candidate.file_path);
        let has_unresolved_symbol = unresolved_symbol_sites.contains(&site);
        let has_resolved_target = resolved_sites.contains(&site);
        let has_explicit_string_contract = explicit_string_contract_reference(line, method_name);
        if !is_definition
            && has_graph_record
            && !has_unresolved_symbol
            && !has_resolved_target
            && !has_explicit_string_contract
        {
            continue;
        }
        let candidate_owner = owner_at_line(graph, &candidate.file_path, line_index + 1);
        if !is_definition
            && !lexical_reference_may_target(
                graph,
                &LexicalReferenceQuery {
                    line,
                    method,
                    target_owner,
                    candidate_owner,
                    allow_unknown_js_ts_member,
                    candidate_file: &candidate.file_path,
                    candidate_line: line_index + 1,
                },
            )
        {
            continue;
        }
        let is_resolved = has_resolved_target;
        let is_resolved_elsewhere = differently_resolved_sites.contains(&site);
        if is_resolved {
            // Graph-confirmed callers are already rendered from MethodRecord::references.
            continue;
        }
        let is_call = !is_definition
            && (has_unresolved_symbol || !has_graph_record)
            && is_lexical_call_site(line, method_name);
        if is_call && !is_resolved && !is_resolved_elsewhere {
            lexical_call_sites.push(evidence.clone());
            lexical_call_locations.push((candidate.file_path.clone(), line_index + 1));
        }
        if is_resolved_elsewhere {
            continue;
        }
        if is_definition && !is_target_definition {
            continue;
        }
        if !is_definition && !is_call {
            non_call_usage.push(evidence.clone());
        }
        if is_test_path(&candidate_lower) && is_call {
            test_usage.push(evidence.clone());
        }
        if !is_definition
            && contains_any(
                &semantic_context,
                &["monkeypatch", "mock", "patch(", "spy("],
            )
        {
            seam_usage.push(evidence.clone());
        }
        if !is_definition
            && contains_any(
                &semantic_context,
                &[
                    "_fn", "callback", "callable", "handler", "factory", "resolver", "strategy",
                    "provider", "inject",
                ],
            )
        {
            callback_usage.push(evidence.clone());
        }
        if !is_definition
            && contains_any(
                &semantic_context,
                &["deprecated", "compat", "legacy", "migration", "alias"],
            )
        {
            compatibility_usage.push(evidence_window.clone());
        }
        if contains_any(
            &semantic_context,
            &["protocol", "interface", "abstract", "override", "trait"],
        ) {
            protocol_usage.push(evidence);
        }
    }
    let (callback_provenance, callback_locations) =
        callback_parameter_provenance(method_name, &file.file_path, index);
    if kotlin_method_declares_override(method) {
        protocol_usage.push(
            "the Kotlin declaration explicitly uses `override`, establishing an interface or superclass contract"
                .to_string(),
        );
    }
    if is_language_protocol_method(method) {
        protocol_usage.push(
            "the Python dunder declaration is invoked implicitly through the language data model"
                .to_string(),
        );
    }
    protocol_usage.extend(go_interface_guards.clone());
    let has_callback_provenance = !callback_provenance.is_empty();
    for evidence in [
        &mut test_usage,
        &mut seam_usage,
        &mut callback_usage,
        &mut compatibility_usage,
        &mut protocol_usage,
        &mut non_call_usage,
        &mut lexical_call_sites,
    ] {
        evidence.sort();
        evidence.dedup();
    }
    facts.push(format!(
        "lexical call-site candidates not confirmed by the symbol graph: {}",
        if_empty(lexical_call_sites.clone())
    ));
    facts.push(format!(
        "lexical call-site provenance chains:\n{}",
        render_lexical_call_chains(file_records, &lexical_call_locations)
    ));
    facts.push(format!(
        "test usage and monkeypatch seams: test references in {}; seam references in {}",
        if_empty(test_usage.clone()),
        if_empty(seam_usage.clone())
    ));
    if !file_test_contract.is_empty() {
        facts.push(format!(
            "file-level test contract evidence (not a method caller): {}",
            if_empty(file_test_contract)
        ));
    }
    if !file_content_test_contract.is_empty() {
        facts.push(format!(
            "tests inspect the containing file's source content: {}",
            if_empty(file_content_test_contract.clone())
        ));
    }
    facts.push(format!(
        "dependency-injection and callback replacement evidence: {}",
        if_empty(callback_usage.clone())
    ));
    facts.push(format!(
        "callback-parameter dataflow evidence: {}",
        if_empty(callback_provenance)
    ));
    facts.push(format!(
        "callback-parameter invocation provenance chains:\n{}",
        render_lexical_call_chains(file_records, &callback_locations)
    ));
    facts.push(format!(
        "compatibility/deprecation evidence: {}",
        if_empty(compatibility_usage.clone())
    ));
    facts.push(format!(
        "interface/protocol/override evidence: {}",
        if_empty(protocol_usage.clone())
    ));
    facts.push(format!(
        "non-call symbol or registration references: {}",
        if_empty(non_call_usage.clone())
    ));

    let import_usage = index
        .imports_by_name
        .get(method_name)
        .into_iter()
        .flatten()
        .filter_map(|location| {
            let import = graph
                .files
                .get(&location.path)?
                .imports
                .get(location.index)?;
            target_definition_id
                .is_some_and(|definition_id| {
                    graph.import_targets_definition(
                        &location.path,
                        location.index,
                        &file.file_path,
                        definition_id,
                    )
                })
                .then(|| {
                    format!(
                        "{}: imports {} as {} from {}",
                        location.path,
                        import.imported_name,
                        import.local_name,
                        import.source_module
                    )
                })
        })
        .collect::<Vec<_>>();
    let reexport_usage = index
        .exports_by_name
        .get(method_name)
        .into_iter()
        .flatten()
        .filter_map(|location| {
            let export = graph
                .files
                .get(&location.path)?
                .exports
                .get(location.index)?;
            target_definition_id
                .is_some_and(|definition_id| {
                    graph.export_targets_definition(
                        &location.path,
                        location.index,
                        &file.file_path,
                        definition_id,
                    ) && (export.source_module.is_some() || has_external_visibility(method))
                })
                .then(|| {
                    format!(
                        "{}: {} exports {} from {}",
                        location.path,
                        export.local_symbol_name,
                        export.exported_name,
                        export
                            .source_module
                            .as_deref()
                            .unwrap_or("local definition")
                    )
                })
        })
        .collect::<Vec<_>>();
    facts.push(format!(
        "imports involving this method: {}",
        if_empty(import_usage.clone())
    ));
    facts.push(format!(
        "exports and re-exports involving this method: {}",
        if_empty(reexport_usage.clone())
    ));

    facts.push(format!(
        "sibling methods in containing file: {} other methods; their definitions are present in the authoritative full file",
        file.methods
            .iter()
            .filter(|candidate| candidate.start_line != method.start_line)
            .count()
    ));

    let comments = method_documentation(file, method, index);
    facts.push(format!(
        "method-specific comments/docs: {}",
        if_empty(comments.clone())
    ));

    let explicit_parameter_discard = python_parameter_discard_block(method).is_some();
    facts.push(format!(
        "explicit parameter-discard block present: {explicit_parameter_discard}"
    ));
    let compatibility_suspected = !compatibility_usage.is_empty()
        || explicit_parameter_discard
        || contains_any(
            &method.source.to_lowercase(),
            &["deprecated", "compat", "legacy", "migration", "alias"],
        )
        || contains_any(
            &file.file_path.to_lowercase(),
            &["compat", "legacy", "migration", "deprecated"],
        );
    let (history, history_established) = if compatibility_suspected {
        git_history(graph, &file.file_path, method_name)
    } else {
        (
            "not queried because no compatibility/migration signal was detected".to_string(),
            false,
        )
    };
    facts.push(format!("git history: {history}"));
    let history_establishes_compatibility =
        history_established && history_describes_compatibility(&history);

    let has_protocol_contract = is_language_protocol_method(method)
        || is_protocol_stub_method(method)
        || is_protocol_surface_module(file)
        || class_contract.is_some()
        || external_framework_contract.is_some()
        || external_object_escape.is_some()
        || !protocol_usage.is_empty()
        || has_parallel_implementation;
    let inline_callback = is_inline_anonymous_callback(method);
    facts.push(if inline_callback {
        "inline callback contract: this synthetic anonymous symbol is consumed by its containing expression; zero separate graph callers is expected and does not require a parent caller"
            .to_string()
    } else {
        "inline callback contract: not an inline anonymous callback".to_string()
    });
    let has_callback_contract = inline_callback
        || object_owner.is_some()
        || inline_object_owner.is_some()
        || !callback_usage.is_empty()
        || has_callback_provenance
        || !seam_usage.is_empty();
    let reexport_establishes_contract = !reexport_usage.is_empty()
        && (!matches!(method.language.as_str(), "javascript" | "typescript")
            || !private_js_ts_package);
    let has_compatibility_contract = !compatibility_usage.is_empty()
        || reexport_establishes_contract
        || history_establishes_compatibility
        || contains_any(
            &comments.join("\n").to_lowercase(),
            &["deprecated", "compat", "legacy", "migration", "alias"],
        );
    if let Some(evidence) = returned_member_evidence.as_deref() {
        facts.push(format!(
            "externally returned member contract evidence: {evidence}"
        ));
    }
    facts.push(format!(
        "resolved returned-member consumers: {}",
        if_empty(returned_member_usage.clone())
    ));
    let returned_surface_sites = returned_surface_entries
        .iter()
        .map(|(line, _)| (file.file_path.to_lowercase(), *line))
        .collect::<HashSet<_>>();
    let effective_real_ref_count = method
        .references
        .iter()
        .filter(|reference| {
            !returned_surface_sites.contains(&(reference.file_path.to_lowercase(), reference.line))
        })
        .count();
    let has_external_contract_evidence = effective_real_ref_count > 0
        || role_based_consumer
        || !lexical_call_sites.is_empty()
        || !test_usage.is_empty()
        || !seam_usage.is_empty()
        || !callback_usage.is_empty()
        || has_callback_provenance
        || !non_call_usage.is_empty()
        || !import_usage.is_empty()
        || !reexport_usage.is_empty()
        || returned_member_evidence.is_some()
        || !returned_member_usage.is_empty()
        || !owner_invocation_evidence.is_empty()
        || !dynamic_import_evidence.is_empty()
        || !commonjs_require_evidence.is_empty()
        || !file_content_test_contract.is_empty()
        || external_framework_contract.is_some()
        || external_object_escape.is_some()
        || object_owner.is_some()
        || inline_object_owner.is_some()
        || !object_owner_usage.is_empty()
        || !go_interface_guards.is_empty()
        || has_compatibility_contract;
    let returned_member_has_external_contract =
        returned_member_evidence.is_some() && !private_js_ts_package;
    let repository_private_unused_candidate = !inline_callback
        && !inline_object_argument_contract
        && !unowned_nested_callable
        && !role_based_consumer
        && !repository_external_visibility
        && !owner_has_repository_external_visibility
        && effective_real_ref_count == 0
        && lexical_call_sites.is_empty()
        && test_usage.is_empty()
        && seam_usage.is_empty()
        && callback_usage.is_empty()
        && !has_callback_provenance
        && non_call_usage.is_empty()
        && import_usage.is_empty()
        && !reexport_establishes_contract
        && !returned_member_has_external_contract
        && returned_member_usage.is_empty()
        && owner_invocation_evidence.is_empty()
        && dynamic_import_evidence.is_empty()
        && commonjs_require_evidence.is_empty()
        && file_content_test_contract.is_empty()
        && enumeration_invocation_proof.is_none()
        && computed_invocation_evidence.is_empty()
        && object_owner_usage.is_empty()
        && go_interface_guards.is_empty()
        && !has_protocol_contract
        && !has_compatibility_contract;
    facts.push(format!(
        "closed-world private-unused candidate for final AI adjudication: {repository_private_unused_candidate}"
    ));

    let stale_discard_signature_proof = python_stale_discard_signature_proof(method)
        .filter(|_| {
            !repository_external_visibility
                && method.real_ref_count > 0
                && method.references.len() == method.real_ref_count
                && lexical_call_sites.is_empty()
                && test_usage.is_empty()
                && seam_usage.is_empty()
                && callback_usage.is_empty()
                && !has_callback_provenance
                && non_call_usage.is_empty()
                && import_usage.is_empty()
                && !reexport_establishes_contract
                && !has_protocol_contract
                && !has_compatibility_contract
        })
        .map(Box::new);
    facts.push(match &stale_discard_signature_proof {
        Some(proof) => format!(
            "closed-world stale discarded-parameter signature proof: established ({})",
            proof.render()
        ),
        None => {
            "closed-world stale discarded-parameter signature proof: not established".to_string()
        }
    });

    RepositoryFacts {
        rendered: facts.join("\n"),
        has_protocol_contract,
        has_callback_contract,
        has_compatibility_contract,
        has_external_contract_evidence,
        has_repository_external_visibility: repository_external_visibility,
        repository_private_unused_candidate,
        stale_discard_signature_proof,
    }
}

fn go_owner_contract_evidence(
    owner: &str,
    index: &DossierRepositoryIndex<'_>,
) -> (Vec<String>, Vec<String>) {
    let construction = format!("{owner}{{");
    let pointer_guard = format!("=(*{owner})(nil)");
    let value_guard = format!("={owner}(nil)");
    let mut constructions = Vec::new();
    let mut guards = Vec::new();

    for (file_index, lines) in index.source_lines.iter().enumerate() {
        for (line_index, line) in lines.iter().enumerate() {
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let evidence = || {
                format!(
                    "{}:{}: {}",
                    index.file_records[file_index].file_path,
                    line_index + 1,
                    line.trim()
                )
            };
            if compact.contains(&pointer_guard) || compact.contains(&value_guard) {
                guards.push(evidence());
            } else if compact.contains(&construction) {
                constructions.push(evidence());
            }
        }
    }

    constructions.sort();
    constructions.dedup();
    guards.sort();
    guards.dedup();
    (constructions, guards)
}

pub(super) fn callback_parameter_provenance(
    method_name: &str,
    target_file: &str,
    index: &DossierRepositoryIndex<'_>,
) -> (Vec<String>, Vec<(String, usize)>) {
    let graph = index.graph;
    let file_records = index.file_records;
    let target_definition_id = graph.files.get(target_file).and_then(|symbols| {
        symbols
            .definitions
            .iter()
            .find(|definition| definition.name == method_name)
            .map(|definition| definition.id)
    });
    let mut aliases = index
        .imports_by_name
        .get(method_name)
        .into_iter()
        .flatten()
        .filter_map(|location| {
            let symbols = graph.files.get(&location.path)?;
            let import = symbols.imports.get(location.index)?;
            (import.imported_name == method_name
                && alias_resolves_to_target(
                    symbols,
                    &import.local_name,
                    target_file,
                    method_name,
                    target_definition_id,
                ))
            .then(|| (location.path.to_lowercase(), import.local_name.clone()))
        })
        .collect::<Vec<_>>();
    if let Some(symbols) = graph.files.get(target_file)
        && alias_resolves_to_target(
            symbols,
            method_name,
            target_file,
            method_name,
            target_definition_id,
        )
    {
        aliases.push((target_file.to_lowercase(), method_name.to_string()));
    }
    aliases.sort();
    aliases.dedup();

    let mut parameters = Vec::new();
    let mut evidence = Vec::new();
    for (path, alias) in aliases {
        let Some(file) = index.file_by_lower_path(&path) else {
            continue;
        };
        for location in index
            .source_locations(&alias)
            .into_iter()
            .filter(|location| {
                file_records[location.file_index]
                    .file_path
                    .eq_ignore_ascii_case(&path)
            })
        {
            let line_index = location.line_index;
            let line = index.source_lines[location.file_index][line_index];
            let Some(parameter) = callback_parameter_assignment(line, &alias) else {
                continue;
            };
            evidence.push(format!(
                "injection site {}:{} links `{alias}` to callback parameter `{parameter}`: {}",
                file.file_path,
                line_index + 1,
                line.trim()
            ));
            parameters.push(parameter);
        }
    }
    parameters.sort();
    parameters.dedup();

    let mut invocation_locations = Vec::new();
    for parameter in parameters {
        for location in index.source_locations(&parameter) {
            let file = &file_records[location.file_index];
            let line = index.source_lines[location.file_index][location.line_index];
            if !is_lexical_call_site(line, &parameter) {
                continue;
            }
            evidence.push(format!(
                "callback invocation through `{parameter}` (lexically linked, not a direct graph call): {}",
                index.source_window(location)
            ));
            invocation_locations.push((file.file_path.clone(), location.line_index + 1));
        }
    }
    evidence.sort();
    evidence.dedup();
    invocation_locations.sort();
    invocation_locations.dedup();
    (evidence, invocation_locations)
}

pub(super) fn alias_resolves_to_target(
    symbols: &crate::types::LocalFileSymbols,
    alias: &str,
    target_file: &str,
    method_name: &str,
    target_definition_id: Option<usize>,
) -> bool {
    symbols.references.iter().any(|reference| {
        if reference.name != alias {
            return false;
        }
        match &reference.resolved_symbol {
            Some(crate::types::ResolvedSymbol::External {
                file_path,
                symbol_name,
                definition_id,
            }) => {
                file_path.eq_ignore_ascii_case(target_file)
                    && symbol_name == method_name
                    && (definition_id.is_none() || *definition_id == target_definition_id)
            }
            Some(crate::types::ResolvedSymbol::Local(definition_id)) => {
                symbols.file_path.eq_ignore_ascii_case(target_file)
                    && Some(*definition_id) == target_definition_id
            }
            None => false,
        }
    })
}

pub(super) fn callback_parameter_assignment(line: &str, callable_alias: &str) -> Option<String> {
    let code = line.split('#').next().unwrap_or(line);
    let (left, right) = code.split_once('=')?;
    let right = right.trim_start();
    let after_alias = right.strip_prefix(callable_alias)?;
    if after_alias.chars().next().is_some_and(is_identifier_char) {
        return None;
    }
    let suffix = after_alias.trim();
    if suffix.starts_with('(')
        || suffix
            .chars()
            .any(|character| !matches!(character, ')' | ']' | '}' | ',' | ';'))
    {
        return None;
    }
    let parameter = left
        .rsplit(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .find(|part| !part.is_empty())?;
    let lower = parameter.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "_fn", "callback", "callable", "handler", "factory", "resolver", "strategy", "provider",
        ],
    )
    .then(|| parameter.to_string())
}

pub(super) fn render_lexical_call_chains(
    file_records: &[FileRecord],
    locations: &[(String, usize)],
) -> String {
    let mut roots = locations.to_vec();
    roots.sort();
    roots.dedup();

    let mut rendered = Vec::new();
    let mut seen_methods = HashSet::new();
    for (path, line) in roots.into_iter().take(MAX_LEXICAL_CALL_ROOTS) {
        let Some((file, method)) = containing_method(file_records, &path, line) else {
            rendered.push(format!(
                "- {path}:{line}: containing method unavailable; no provenance chain established"
            ));
            continue;
        };
        render_upstream_method_chain(
            file_records,
            file,
            method,
            line,
            0,
            &mut seen_methods,
            &mut rendered,
        );
        if seen_methods.len() >= MAX_LEXICAL_CHAIN_METHODS {
            break;
        }
    }

    if rendered.is_empty() {
        "none established".to_string()
    } else {
        rendered.join("\n")
    }
}

pub(super) fn render_upstream_method_chain(
    file_records: &[FileRecord],
    file: &FileRecord,
    method: &MethodRecord,
    call_line: usize,
    depth: usize,
    seen_methods: &mut HashSet<(String, usize)>,
    rendered: &mut Vec<String>,
) {
    if seen_methods.len() >= MAX_LEXICAL_CHAIN_METHODS {
        return;
    }
    let key = (file.file_path.to_lowercase(), method.start_line);
    if !seen_methods.insert(key) {
        return;
    }

    let relation = if depth == 0 {
        "lexical call is inside"
    } else {
        "resolved upstream caller"
    };
    if method.source.lines().count() <= 13 {
        rendered.push(format!(
            "- {relation} {}::{} lines {}-{} (full method):\n{}",
            file.file_path,
            method.name,
            method.start_line,
            method.end_line,
            numbered_source(&method.source, method.start_line)
        ));
    } else {
        rendered.push(format!(
            "- {relation} {}::{} lines {}-{}; call site line {} (bounded context):\n{}",
            file.file_path,
            method.name,
            method.start_line,
            method.end_line,
            call_line,
            bounded_call_site_context(file, method, call_line)
        ));
    }

    if depth >= MAX_LEXICAL_CHAIN_DEPTH {
        return;
    }
    let mut callers = method.references.clone();
    callers.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then(left.line.cmp(&right.line))
    });
    callers.dedup_by(|left, right| {
        left.file_path.eq_ignore_ascii_case(&right.file_path) && left.line == right.line
    });
    for caller in callers {
        if seen_methods.len() >= MAX_LEXICAL_CHAIN_METHODS {
            break;
        }
        let Some((caller_file, caller_method)) =
            containing_method(file_records, &caller.file_path, caller.line)
        else {
            rendered.push(format!(
                "- resolved upstream reference {}:{} could not be mapped to a parsed method: {}",
                caller.file_path, caller.line, caller.snippet
            ));
            continue;
        };
        render_upstream_method_chain(
            file_records,
            caller_file,
            caller_method,
            caller.line,
            depth + 1,
            seen_methods,
            rendered,
        );
    }
}

pub(super) fn bounded_call_site_context(
    file: &FileRecord,
    method: &MethodRecord,
    call_line: usize,
) -> String {
    let lines = file.source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return "source unavailable".to_string();
    }

    let method_start = method.start_line.saturating_sub(1).min(lines.len());
    let method_end = method.end_line.min(lines.len());
    let call_index = call_line
        .saturating_sub(1)
        .clamp(method_start, method_end.saturating_sub(1));
    let start = call_index.saturating_sub(2).max(method_start);
    let end = (call_index + 11).min(method_end);
    (start..end)
        .map(|index| format!("{} | {}", index + 1, lines[index]))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn containing_method<'a>(
    file_records: &'a [FileRecord],
    path: &str,
    line: usize,
) -> Option<(&'a FileRecord, &'a MethodRecord)> {
    let file = file_records
        .iter()
        .find(|candidate| candidate.file_path.eq_ignore_ascii_case(path))?;
    let method = file
        .methods
        .iter()
        .filter(|candidate| candidate.start_line <= line && line <= candidate.end_line)
        .min_by_key(|candidate| candidate.end_line.saturating_sub(candidate.start_line))?;
    Some((file, method))
}

pub(super) fn method_documentation(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let fallback;
    let lines = if let Some(file_index) = index
        .files_by_lower_path
        .get(&file.file_path.to_lowercase())
    {
        &index.source_lines[*file_index]
    } else {
        fallback = file.source.lines().collect::<Vec<_>>();
        &fallback
    };
    let mut documentation = Vec::new();
    let mut cursor = method.start_line.saturating_sub(1);
    while cursor > 0 {
        let line = lines.get(cursor - 1).copied().unwrap_or("");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if is_documentation_line(trimmed) {
            documentation.push(format!("{}: {}", cursor, trimmed));
            cursor -= 1;
            continue;
        }
        break;
    }
    documentation.reverse();

    for (offset, line) in method.source.lines().enumerate() {
        let trimmed = line.trim();
        if is_documentation_line(trimmed)
            || trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("'''")
        {
            documentation.push(format!("{}: {}", method.start_line + offset, trimmed));
        }
    }
    documentation
}

pub(super) fn is_documentation_line(line: &str) -> bool {
    line.starts_with('#')
        || line.starts_with("//")
        || line.starts_with("/*")
        || line.starts_with('*')
        || line.starts_with("///")
        || line.starts_with("//!")
        || line.starts_with("@Deprecated")
        || line.starts_with("#[deprecated")
}

pub(super) fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("test/")
        || normalized.starts_with("tests/")
        || normalized.starts_with("spec/")
        || normalized.starts_with("specs/")
        || normalized.contains("/test")
        || path.contains("\\test")
        || normalized.contains("/spec")
        || path.contains("\\spec")
        || normalized.contains("__tests__")
        || normalized.contains("_test.")
}

pub(super) fn contains_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| source.contains(needle))
}

pub(super) fn history_describes_compatibility(history: &str) -> bool {
    contains_any(
        &history.to_lowercase(),
        &[
            "compat",
            "deprecated",
            "legacy",
            "migration",
            "alias",
            "rename",
            "preserve",
        ],
    )
}

pub(super) fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

pub(super) fn identifier_matches<'a>(
    source: &'a str,
    identifier: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    source
        .match_indices(identifier)
        .filter_map(move |(start, matched)| {
            let before = source[..start].chars().next_back();
            let end = start + matched.len();
            let after = source[end..].chars().next();
            let bounded_before = before.is_none_or(|ch| !is_identifier_char(ch));
            let bounded_after = after.is_none_or(|ch| !is_identifier_char(ch));
            (bounded_before && bounded_after).then_some(end)
        })
}

pub(super) fn contains_identifier(source: &str, identifier: &str) -> bool {
    !identifier.is_empty() && identifier_matches(source, identifier).next().is_some()
}

pub(super) fn context_without_target_identifier(source: &str, identifier: &str) -> String {
    let mut context = source.to_string();
    let matches = identifier_matches(source, identifier).collect::<Vec<_>>();
    for end in matches.into_iter().rev() {
        context.replace_range(end - identifier.len()..end, "<target>");
    }
    context.to_lowercase()
}

#[cfg(test)]
pub(super) fn source_window(file: &FileRecord, line_index: usize) -> String {
    let lines = file.source.lines().collect::<Vec<_>>();
    let start = line_index.saturating_sub(2);
    let end = (line_index + 11).min(lines.len());
    (start..end)
        .map(|index| {
            format!(
                "{}:{}: {}",
                file.file_path,
                index + 1,
                lines[index].trim_end()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
