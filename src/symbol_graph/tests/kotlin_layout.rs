use super::*;

#[test]
fn test_kotlin_object_qualified_call_resolves_to_owned_method() {
    let dir = unique_tag("temp_kotlin_object_call");
    fs::create_dir_all(&dir).unwrap();
    let coordinator = write_temp_file(
        &dir,
        "Coordinator.kt",
        "package sample\n\ninternal object Coordinator {\n  fun build(value: String): String = value\n}\n\nfun build(value: String): String = value\n",
    );
    let caller = write_temp_file(
        &dir,
        "Caller.kt",
        "package sample\n\nfun useCoordinator(): String = Coordinator.build(\"value\")\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&coordinator));
    graph.add_file(parse_file_symbols(&caller));
    graph.resolve_all();

    let coordinator_symbols = graph.files.get(&coordinator).unwrap();
    let owned_id = coordinator_symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "build" && definition.owner_type.as_deref() == Some("Coordinator")
        })
        .expect("owned Coordinator.build definition")
        .id;
    let top_level_id = coordinator_symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "build" && definition.owner_type.is_none())
        .expect("top-level build definition")
        .id;
    assert_ne!(owned_id, top_level_id);

    let reference = graph
        .files
        .get(&caller)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "Coordinator.build")
        .expect("qualified Kotlin call");
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External {
            file_path,
            definition_id,
            ..
        }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&coordinator));
            assert_eq!(*definition_id, Some(owned_id));
        }
        other => panic!("expected owned Kotlin method, got {other:?}"),
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_callable_references_resolve_to_owned_methods() {
    let dir = unique_tag("temp_kotlin_callable_reference");
    fs::create_dir_all(&dir).unwrap();
    let coordinator = write_temp_file(
        &dir,
        "Coordinator.kt",
        "package sample\n\ninternal object Coordinator {\n  fun convertAll(values: List<String>) = values.map(::convert)\n  fun convert(value: String): String = value\n}\n",
    );
    let caller = write_temp_file(
        &dir,
        "Caller.kt",
        "package sample\n\nfun convertOutside(values: List<String>) = values.map(Coordinator::convert)\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&coordinator));
    graph.add_file(parse_file_symbols(&caller));
    graph.resolve_all();

    let coordinator_symbols = graph.files.get(&coordinator).unwrap();
    let convert_id = coordinator_symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "convert" && definition.owner_type.as_deref() == Some("Coordinator")
        })
        .expect("owned Coordinator.convert definition")
        .id;
    let local_reference = coordinator_symbols
        .references
        .iter()
        .find(|reference| reference.name == "convert")
        .expect("unqualified callable reference");
    assert!(matches!(
        local_reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == convert_id
    ));

    let external_reference = graph
        .files
        .get(&caller)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "Coordinator.convert")
        .expect("qualified callable reference");
    match external_reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External {
            file_path,
            definition_id,
            ..
        }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&coordinator));
            assert_eq!(*definition_id, Some(convert_id));
        }
        other => panic!("expected owned Kotlin callable target, got {other:?}"),
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_typed_receivers_resolve_without_cross_owner_name_matches() {
    let dir = unique_tag("temp_kotlin_typed_receiver");
    fs::create_dir_all(&dir).unwrap();
    let cache = write_temp_file(
        &dir,
        "MedicationPhotoImageCache.kt",
        "package sample\n\nclass MedicationPhotoImageCache {\n  fun put(key: String, value: String) = Unit\n}\n",
    );
    let consumer = write_temp_file(
        &dir,
        "Consumer.kt",
        "package sample\n\nclass JSONObject {\n  fun put(key: String, value: String) = Unit\n}\n\nfun save(cache: MedicationPhotoImageCache) {\n  cache.put(\"key\", \"value\")\n  val payload = JSONObject()\n  payload.put(\"key\", \"value\")\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&cache));
    graph.add_file(parse_file_symbols(&consumer));
    graph.resolve_all();

    let cache_symbols = graph.files.get(&cache).unwrap();
    let cache_put_id = cache_symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "put"
                && definition.owner_type.as_deref() == Some("MedicationPhotoImageCache")
        })
        .expect("cache put definition")
        .id;
    let consumer_symbols = graph.files.get(&consumer).unwrap();
    assert!(consumer_symbols.definitions.iter().any(|definition| {
        definition.name == "cache"
            && definition.value_type.as_deref() == Some("MedicationPhotoImageCache")
    }));
    assert!(consumer_symbols.definitions.iter().any(|definition| {
        definition.name == "payload" && definition.value_type.as_deref() == Some("JSONObject")
    }));

    let cache_call = consumer_symbols
        .references
        .iter()
        .find(|reference| reference.name == "cache.put")
        .expect("typed cache call");
    assert!(matches!(
        cache_call.resolved_symbol,
        Some(ResolvedSymbol::External {
            definition_id: Some(id),
            ..
        }) if id == cache_put_id
    ));

    let payload_call = consumer_symbols
        .references
        .iter()
        .find(|reference| reference.name == "payload.put")
        .expect("typed payload call");
    assert!(!matches!(
        payload_call.resolved_symbol,
        Some(ResolvedSymbol::External {
            definition_id: Some(id),
            ..
        }) if id == cache_put_id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_imported_top_level_call_resolves_to_the_named_package() {
    let dir = unique_tag("temp_kotlin_top_level_call");
    fs::create_dir_all(&dir).unwrap();
    let provider = write_temp_file(
        &dir,
        "Provider.kt",
        "\u{feff}package sample\n\nfun rememberProvider(): String = \"provider\"\n",
    );
    let caller = write_temp_file(
        &dir,
        "Caller.kt",
        "package screen\n\nimport sample.rememberProvider\n\nfun screen(): String = rememberProvider()\n",
    );
    let other = write_temp_file(
        &dir,
        "Other.kt",
        "package other\n\nfun rememberProvider(): String = \"other\"\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&provider));
    graph.add_file(parse_file_symbols(&caller));
    graph.add_file(parse_file_symbols(&other));
    graph.resolve_all();

    let provider_id = graph
        .files
        .get(&provider)
        .unwrap()
        .definitions
        .iter()
        .find(|definition| definition.name == "rememberProvider")
        .expect("top-level provider definition")
        .id;
    let reference = graph
        .files
        .get(&caller)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "rememberProvider")
        .expect("top-level provider call");
    let import = graph
        .files
        .get(&caller)
        .unwrap()
        .imports
        .first()
        .expect("named Kotlin import");
    assert_eq!(import.source_module, "sample");
    assert_eq!(import.imported_name, "rememberProvider");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::External {
            definition_id: Some(id),
            ..
        }) if id == provider_id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_function_declaration_is_not_a_call_but_same_line_recursion_is() {
    let dir = unique_tag("temp_kotlin_recursive_call");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Recursive.kt",
        "package sample\n\n@Deprecated(\"fixture\")\nfun recur(): Unit = recur()\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let references = symbols
        .references
        .iter()
        .filter(|reference| reference.name == "recur")
        .collect::<Vec<_>>();
    assert_eq!(references.len(), 1);
    assert!(matches!(
        references[0].resolved_symbol,
        Some(ResolvedSymbol::Local(_))
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_annotated_kotlin_function_declaration_is_not_a_self_reference() {
    let dir = unique_tag("temp_kotlin_annotated_declaration");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Preview.kt",
        "package sample\n\n@Composable\ninternal fun medicationPhotoPreview(\n  reference: String,\n  modifier: Modifier = Modifier,\n) {\n  val image = reference.ifBlank { modifier.toString() }\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "medicationPhotoPreview")
    );
    assert!(
        !symbols
            .references
            .iter()
            .any(|reference| reference.name == "medicationPhotoPreview"),
        "annotated declaration became a reference: {:?}",
        symbols.references
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_default_lambda_parameter_inherits_function_input_type() {
    let dir = unique_tag("temp_kotlin_typed_default_lambda");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Coordinator.kt",
        "package sample\n\nclass Shadow {\n  fun onAppLaunched() = Unit\n}\n\nfun launch(\n  build: (Shadow) -> Unit = { shadow -> shadow.onAppLaunched() },\n) = build(Shadow())\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let launched = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "onAppLaunched")
        .expect("Shadow.onAppLaunched definition");
    assert!(symbols.definitions.iter().any(|definition| {
        definition.name == "shadow" && definition.value_type.as_deref() == Some("Shadow")
    }));
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "shadow.onAppLaunched")
        .expect("typed default-lambda call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == launched.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_default_callback_reference_survives_matching_parameter_name() {
    let dir = unique_tag("temp_kotlin_matching_callback_name");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Coordinator.kt",
        "package sample\n\nobject Runtime {\n  fun launch() = Unit\n}\n\nfun boot(\n  launch: () -> Unit = Runtime::launch,\n) = launch()\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let launch = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "launch" && definition.owner_type.as_deref() == Some("Runtime")
        })
        .expect("Runtime.launch definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "Runtime.launch")
        .expect("default callable reference");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == launch.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_generic_current_receiver_projects_to_payload_type() {
    let dir = unique_tag("temp_kotlin_generic_receiver");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Localization.kt",
        "package sample\n\nclass LocalizedStrings {\n  fun text(key: String): String = key\n}\n\nval LocalStrings: ProvidableCompositionLocal<LocalizedStrings> = provider()\n\nfun localized(key: String): String = LocalStrings.current.text(key)\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let text_id = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "text"
                && definition.owner_type.as_deref() == Some("LocalizedStrings")
        })
        .expect("LocalizedStrings.text definition")
        .id;
    assert!(symbols.definitions.iter().any(|definition| {
        definition.name == "LocalStrings"
            && definition.value_type.as_deref()
                == Some("ProvidableCompositionLocal<LocalizedStrings>")
    }));
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "LocalStrings.current.text")
        .expect("generic current receiver call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == text_id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_string_template_calls_resolve_to_the_enclosing_object_method() {
    let dir = unique_tag("temp_kotlin_template_call");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Runtime.kt",
        "package sample\n\nobject Runtime {\n  fun filename(now: Long): String = \"snapshot_${timestamp(now)}.json\"\n  private fun timestamp(value: Long): String = value.toString()\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let timestamp = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "timestamp" && definition.owner_type.as_deref() == Some("Runtime")
        })
        .expect("Runtime.timestamp definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "timestamp")
        .expect("call inside Kotlin string template");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == timestamp.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_nested_property_extension_call_resolves_by_receiver_type() {
    let dir = unique_tag("temp_kotlin_nested_extension");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Labels.kt",
        "package sample\n\nenum class Reason { READY }\ndata class Decision(val reason: Reason)\n\nfun render(decision: Decision): String = \"status ${decision.reason.label()}\"\nprivate fun Reason.label(): String = name\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let label = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "label" && definition.receiver_type.as_deref() == Some("Reason")
        })
        .expect("Reason.label extension definition");
    let reason = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "reason" && definition.owner_type.as_deref() == Some("Decision")
        })
        .expect("Decision.reason property definition");
    assert_eq!(reason.value_type.as_deref(), Some("Reason"));
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "decision.reason.label")
        .expect("nested receiver extension call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == label.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_unqualified_call_ignores_same_named_property() {
    let dir = unique_tag("temp_kotlin_property_collision");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Planner.kt",
        "package sample\n\ndata class Presentation(val nextDueLabel: String)\nobject Planner {\n  fun plan(): Presentation = Presentation(nextDueLabel = nextDueLabel())\n  private fun nextDueLabel(): String = \"soon\"\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let method = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "nextDueLabel" && definition.owner_type.as_deref() == Some("Planner")
        })
        .expect("Planner.nextDueLabel definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "nextDueLabel")
        .expect("unqualified nextDueLabel call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == method.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_same_named_extensions_do_not_cross_receiver_types() {
    let dir = unique_tag("temp_kotlin_extension_owners");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Permissions.kt",
        "package sample\n\nclass ReadIntent\nclass WriteIntent\nobject ReadPolicy {\n  fun check(intent: ReadIntent): Boolean = intent.requiresPermission()\n  private fun ReadIntent.requiresPermission(): Boolean = false\n}\nobject WritePolicy {\n  fun check(intent: WriteIntent): Boolean = intent.requiresPermission()\n  private fun WriteIntent.requiresPermission(): Boolean = true\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let read_id = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "requiresPermission"
                && definition.receiver_type.as_deref() == Some("ReadIntent")
        })
        .expect("ReadIntent extension")
        .id;
    let write_id = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "requiresPermission"
                && definition.receiver_type.as_deref() == Some("WriteIntent")
        })
        .expect("WriteIntent extension")
        .id;
    let calls = symbols
        .references
        .iter()
        .filter(|reference| reference.name == "intent.requiresPermission")
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    assert!(matches!(calls[0].resolved_symbol, Some(ResolvedSymbol::Local(id)) if id == read_id));
    assert!(matches!(calls[1].resolved_symbol, Some(ResolvedSymbol::Local(id)) if id == write_id));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_constructor_result_member_call_resolves_to_the_constructed_type() {
    let dir = unique_tag("temp_kotlin_constructor_member");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Restore.kt",
        "package sample\n\nclass HostAdherenceStore {\n  fun replaceAll(events: List<String>) = Unit\n}\n\nfun restore(events: List<String>) {\n  HostAdherenceStore().replaceAll(events)\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let replace_all = symbols
        .definitions
        .iter()
        .find(|definition| {
            definition.name == "replaceAll"
                && definition.owner_type.as_deref() == Some("HostAdherenceStore")
        })
        .expect("HostAdherenceStore.replaceAll definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "HostAdherenceStore.replaceAll")
        .expect("constructor-result member call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == replace_all.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_multiline_object_qualified_call_remains_resolvable() {
    let dir = unique_tag("temp_kotlin_multiline_object_member");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Projection.kt",
        "package sample\n\nobject DoseProjectionEngine {\n  fun terminalHistory(events: List<String>): List<String> = events\n}\n\nfun project(events: List<String>): List<String> =\n  DoseProjectionEngine\n    .terminalHistory(events)\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let terminal_history = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "terminalHistory")
        .expect("DoseProjectionEngine.terminalHistory definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "DoseProjectionEngine.terminalHistory")
        .expect("multiline object-qualified call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == terminal_history.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_method_return_type_projects_nested_receiver_calls() {
    let dir = unique_tag("temp_kotlin_method_return_projection");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Runtime.kt",
        "package sample\n\nclass Shell {\n  fun onOnboardingStateSelected(state: String) = Unit\n}\n\nclass Runtime {\n  fun shell(): Shell = Shell()\n}\n\nfun select(runtime: Runtime, state: String) {\n  runtime.shell().onOnboardingStateSelected(state)\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    assert!(symbols.definitions.iter().any(|definition| {
        definition.name == "shell" && definition.value_type.as_deref() == Some("Shell")
    }));
    let selected = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "onOnboardingStateSelected")
        .expect("Shell.onOnboardingStateSelected definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "runtime.shell.onOnboardingStateSelected")
        .expect("nested method-result receiver call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == selected.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_top_level_property_lambda_calls_are_indexed() {
    let dir = unique_tag("temp_kotlin_property_lambda_call");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Savers.kt",
        "package sample\n\ninternal val stateSaver = listSaver(restore = { saved -> parseState(saved) })\n\ninternal fun parseState(value: String): String = value\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let parse_state = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "parseState")
        .expect("parseState definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "parseState" && reference.line == 3)
        .expect("top-level property lambda call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == parse_state.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_class_property_initializer_calls_companion_method() {
    let dir = unique_tag("temp_kotlin_class_property_call");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Surface.kt",
        "package sample\n\ndata class SurfaceState(val value: String) {\n  companion object {\n    fun empty(): SurfaceState = SurfaceState(\"\")\n  }\n}\n\nclass Surface {\n  private val state = SurfaceState.empty()\n}\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let empty = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "empty")
        .expect("SurfaceState.empty definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "SurfaceState.empty")
        .expect("class property initializer call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == empty.id
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_kotlin_trailing_lambda_extension_call_is_indexed() {
    let dir = unique_tag("temp_kotlin_trailing_lambda_extension");
    fs::create_dir_all(&dir).unwrap();
    let source = write_temp_file(
        &dir,
        "Cursor.kt",
        "package sample\n\nclass Cursor\n\nfun read(cursor: Cursor): String = cursor.useCursor { \"value\" }\n\ninternal inline fun <T> Cursor.useCursor(block: (Cursor) -> T): T = block(this)\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let use_cursor = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "useCursor")
        .expect("Cursor.useCursor definition");
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "cursor.useCursor")
        .expect("trailing-lambda extension call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == use_cursor.id
    ));
    fs::remove_dir_all(&dir).ok();
}
