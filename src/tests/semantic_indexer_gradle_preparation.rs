use super::cache::transfer_cache;
use super::control_plane::{KotlinDependencyPreparationError, stage_control_plane};
use super::settings::include_build_literals;
use std::fs;
use std::path::Path;

fn preparation_error_detail(error: &KotlinDependencyPreparationError) -> &str {
    match error {
        KotlinDependencyPreparationError::RepositoryRejected(detail)
        | KotlinDependencyPreparationError::InfrastructureFailed(detail) => detail,
    }
}

#[test]
fn source_minimized_stage_keeps_build_logic_but_not_application_source_or_secrets() {
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path();
    fs::write(
        root.join("settings.gradle.kts"),
        "pluginManagement { includeBuild(\"build-logic\") }\ninclude(\":app\")\n",
    )
    .unwrap();
    fs::write(root.join("build.gradle.kts"), "plugins { base }\n").unwrap();
    fs::write(
        root.join("gradle.properties"),
        "org.gradle.parallel=true\nrepositoryPassword=do-not-copy\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("gradle")).unwrap();
    fs::write(
        root.join("gradle/libs.versions.toml"),
        "[versions]\nkotlin='2.2.0'\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("app/src/main/kotlin")).unwrap();
    fs::write(
        root.join("app/build.gradle.kts"),
        "plugins { kotlin(\"jvm\") }\n",
    )
    .unwrap();
    fs::write(root.join("app/src/main/kotlin/App.kt"), "class App\n").unwrap();
    fs::write(root.join(".env"), "TOKEN=do-not-copy\n").unwrap();
    fs::create_dir_all(root.join("buildSrc/src/main/kotlin")).unwrap();
    fs::write(
        root.join("buildSrc/src/main/kotlin/RootPlugin.kt"),
        "class RootPlugin\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("build-logic/src/main/kotlin")).unwrap();
    fs::write(
        root.join("build-logic/settings.gradle.kts"),
        "rootProject.name=\"logic\"\n",
    )
    .unwrap();
    fs::write(
        root.join("build-logic/build.gradle.kts"),
        "plugins { `kotlin-dsl` }\n",
    )
    .unwrap();
    fs::write(
        root.join("build-logic/src/main/kotlin/Convention.kt"),
        "class Convention\n",
    )
    .unwrap();

    let target = root.join(".sniff-indexer-tmp/preparation");
    stage_control_plane(root, &target).unwrap();

    assert!(target.join("settings.gradle.kts").is_file());
    assert!(target.join("app/build.gradle.kts").is_file());
    assert!(
        target
            .join("app/src/main/java/SniffDependencyJavaProbe1.java")
            .is_file()
    );
    assert!(
        target
            .join("app/src/main/kotlin/SniffDependencyKotlinProbe1.kt")
            .is_file()
    );
    assert!(
        target
            .join("buildSrc/src/main/kotlin/RootPlugin.kt")
            .is_file()
    );
    assert!(
        target
            .join("build-logic/src/main/kotlin/Convention.kt")
            .is_file()
    );
    assert!(!target.join("app/src/main/kotlin/App.kt").exists());
    assert!(!target.join(".env").exists());
    let properties = fs::read_to_string(target.join("gradle.properties")).unwrap();
    assert!(properties.contains("org.gradle.parallel=true"));
    assert!(!properties.contains("repositoryPassword"));
    assert!(!properties.contains("do-not-copy"));
}

#[test]
fn dynamic_included_builds_fail_closed() {
    let error = include_build_literals(
        "includeBuild(providers.gradleProperty(\"logicPath\"))\n",
        Path::new("settings.gradle.kts"),
    )
    .unwrap_err();
    assert!(error.contains("dynamic includeBuild"));
}

#[test]
fn repository_escaping_included_builds_fail_closed() {
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path();
    fs::write(
        root.join("settings.gradle.kts"),
        "includeBuild(\"../outside\")\n",
    )
    .unwrap();

    let error =
        stage_control_plane(root, &root.join(".sniff-indexer-tmp/preparation")).unwrap_err();
    assert!(preparation_error_detail(&error).contains("repository-relative child path"));
}

#[test]
fn likely_credentials_in_build_logic_never_enter_preparation() {
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path();
    fs::write(
        root.join("settings.gradle.kts"),
        "rootProject.name=\"unsafe\"\n",
    )
    .unwrap();
    fs::write(
        root.join("build.gradle.kts"),
        "val api_key = \"ghp_123456789012345678901234567890123456\"\n",
    )
    .unwrap();

    let error =
        stage_control_plane(root, &root.join(".sniff-indexer-tmp/preparation")).unwrap_err();
    assert!(preparation_error_detail(&error).contains("likely GitHub token"));
    assert!(!preparation_error_detail(&error).contains("123456789012345678901234567890123456"));
}

#[test]
fn kotlin_sources_without_a_root_gradle_project_are_repository_rejections() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join(".sniff-indexer-tmp/preparation");

    let error = stage_control_plane(repository.path(), &target).unwrap_err();

    assert!(matches!(
        error,
        KotlinDependencyPreparationError::RepositoryRejected(_)
    ));
    assert!(preparation_error_detail(&error).contains("repository-root"));
}

#[test]
fn settings_without_a_compilable_gradle_project_are_repository_rejections() {
    let repository = tempfile::tempdir().unwrap();
    fs::write(
        repository.path().join("settings.gradle.kts"),
        "rootProject.name = \"scripts-only\"\n",
    )
    .unwrap();
    let target = repository.path().join(".sniff-indexer-tmp/preparation");

    let error = stage_control_plane(repository.path(), &target).unwrap_err();

    assert!(matches!(
        error,
        KotlinDependencyPreparationError::RepositoryRejected(_)
    ));
    assert!(preparation_error_detail(&error).contains("no build.gradle"));
}

#[test]
fn cache_transfer_removes_preparation_paths_and_preserves_dependencies() {
    let repository = tempfile::tempdir().unwrap();
    let source = repository.path().join("preparation-cache");
    let destination = repository.path().join("offline-cache");
    fs::create_dir_all(source.join("modules/files")).unwrap();
    fs::create_dir_all(source.join(".tmp")).unwrap();
    fs::create_dir_all(source.join("project-cache")).unwrap();
    fs::write(source.join("modules/files/dependency.jar"), b"dependency").unwrap();
    fs::write(source.join(".tmp/stale"), b"temporary").unwrap();
    fs::write(source.join("project-cache/path"), b"preparation-root").unwrap();
    fs::write(
        source.join("gradle.properties"),
        b"systemProp.user.home=preparation\n",
    )
    .unwrap();

    transfer_cache(&source, &destination).unwrap();

    assert!(!source.exists());
    assert_eq!(
        fs::read(destination.join("modules/files/dependency.jar")).unwrap(),
        b"dependency"
    );
    assert!(!destination.join(".tmp").exists());
    assert!(!destination.join("project-cache").exists());
    assert!(!destination.join("gradle.properties").exists());
}

#[cfg(unix)]
#[test]
fn cache_transfer_rejects_symlinks_without_creating_a_destination() {
    use std::os::unix::fs::symlink;

    let repository = tempfile::tempdir().unwrap();
    let source = repository.path().join("preparation-cache");
    let destination = repository.path().join("offline-cache");
    fs::create_dir_all(&source).unwrap();
    fs::write(repository.path().join("outside"), b"outside").unwrap();
    symlink(repository.path().join("outside"), source.join("escaped")).unwrap();

    let error = transfer_cache(&source, &destination).unwrap_err();
    assert!(error.contains("linked or reparse-point"));
    assert!(!destination.exists());
}
