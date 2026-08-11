use crate::semantic_indexer_installation::{InstalledIndexer, SemanticIndexerStore};
use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, PinnedIndexer, pinned_indexer,
};
use crate::types::FileRecord;
use flate2::read::GzDecoder;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
#[cfg(windows)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use zip::ZipArchive;

#[path = "semantic_indexer_go_installer.rs"]
mod go_installer;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) async fn install_required_indexers(
    files: &[FileRecord],
    force: bool,
) -> Result<Vec<InstalledIndexer>, String> {
    let store = SemanticIndexerStore::for_user()?;
    let mut installed = Vec::new();
    for kind in crate::semantic_indexer_manifest::required_indexers(files) {
        let spec = pinned_indexer(kind)?;
        installed.push(install_one(&store, spec, force).await?);
    }
    Ok(installed)
}

async fn install_one(
    store: &SemanticIndexerStore,
    spec: PinnedIndexer,
    force: bool,
) -> Result<InstalledIndexer, String> {
    if let Ok(installed) = store.verify(spec) {
        return Ok(installed);
    }
    let final_root = store.installation_root(spec);
    prepare_existing_installation(&final_root, force, spec)?;
    let staging_root = create_staging_directory(&final_root, spec)?;
    let result = async {
        install_source(spec, &staging_root).await?;
        store.seal_at(spec, &staging_root)?;
        store.promote_staged(spec, &staging_root)
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging_root);
    }
    result
}

fn prepare_existing_installation(
    final_root: &Path,
    force: bool,
    spec: PinnedIndexer,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(final_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect existing {} installation {}: {error}",
                spec.display_name,
                final_root.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "refusing to replace non-directory {} installation {}",
            spec.display_name,
            final_root.display()
        ));
    }
    if !force {
        return Err(format!(
            "{} installation exists but is invalid at {}; rerun with --force",
            spec.display_name,
            final_root.display()
        ));
    }
    fs::remove_dir_all(final_root).map_err(|error| {
        format!(
            "failed to remove invalid {} installation {}: {error}",
            spec.display_name,
            final_root.display()
        )
    })
}

fn create_staging_directory(final_root: &Path, spec: PinnedIndexer) -> Result<PathBuf, String> {
    let parent = final_root.parent().ok_or_else(|| {
        format!(
            "semantic indexer installation has no parent: {}",
            final_root.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create semantic indexer directory {}: {error}",
            parent.display()
        )
    })?;
    for sequence in 0..100_u32 {
        let candidate = parent.join(format!(".{}.staging-{sequence}", spec.version));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create {} staging directory {}: {error}",
                    spec.display_name,
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "could not allocate a staging directory for {}",
        spec.display_name
    ))
}

async fn install_source(spec: PinnedIndexer, root: &Path) -> Result<(), String> {
    match spec.source {
        IndexerInstallSource::Npm { package, .. } => install_npm(spec, root, package).await,
        IndexerInstallSource::GoModule {
            module,
            package,
            commit,
        } => go_installer::install(spec, root, module, package, commit).await,
        IndexerInstallSource::Download(download) => install_download(spec, root, download).await,
    }?;
    #[cfg(windows)]
    if spec.kind == crate::semantic_indexer_manifest::SemanticIndexerKind::Kotlin {
        patch_scip_java_windows(root, spec)?;
    }
    Ok(())
}

#[cfg(windows)]
const WINDOWS_SCIP_JAVA_WRITER: &str = r#"package org.scip_code.scip_java.aggregator;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.scip_code.scip.Index;

public class ScipWriter implements AutoCloseable {
  private final Path tmp;
  private final ScipOutputStream output;
  private final ScipAggregatorOptions options;

  public ScipWriter(ScipAggregatorOptions options) throws IOException {
    this.tmp = Files.createTempFile("scip-aggregator", "index.scip");
    this.output = new ScipOutputStream(new BufferedOutputStream(Files.newOutputStream(tmp)));
    this.options = options;
  }

  public void emitTyped(Index index) {
    this.output.write(index.toByteArray());
  }

  public void build() throws IOException {
    close();
    Files.move(tmp, options.output(), StandardCopyOption.REPLACE_EXISTING);
  }

  @Override
  public void close() throws IOException {
    output.flush();
  }

  public void flush() {
    try {
      output.flush();
    } catch (IOException e) {
      options.reporter().error(e);
    }
  }
}
"#;

#[cfg(windows)]
const WINDOWS_SCIP_JAVA_PROCESS_RUNNER: &str = r#"package org.scip_code.scip_java.buildtools;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

public final class ProcessRunner {
  public static final ProcessRunner INSTANCE = new ProcessRunner();
  private static final String BASE_JVM_OPTIONS =
      "--add-opens=java.base/java.util=ALL-UNNAMED "
          + "--add-opens=java.base/java.lang=ALL-UNNAMED "
          + "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED "
          + "--add-opens=java.prefs/java.util.prefs=ALL-UNNAMED "
          + "--add-opens=java.base/java.nio.charset=ALL-UNNAMED "
          + "--add-opens=java.base/java.net=ALL-UNNAMED "
          + "--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED "
          + "-Xmx512m -XX:MaxMetaspaceSize=384m -Dfile.encoding=US-ASCII "
          + "-Duser.country=US -Duser.language=en -Duser.variant=";

  private ProcessRunner() {}

  public final ProcessResult run(
      List<String> command,
      Path cwd,
      Map<String, String> env,
      Function1<? super String, Unit> onStdout,
      Function1<? super String, Unit> onStderr) {
    List<String> effective = rewriteGradleCommand(command);
    ProcessBuilder builder = new ProcessBuilder(effective).directory(cwd.toFile());
    builder.environment().putAll(env);
    try {
      Process process = builder.start();
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<?> stdout = pool.submit(() -> drain(process.getInputStream(), onStdout));
        Future<?> stderr = pool.submit(() -> drain(process.getErrorStream(), onStderr));
        int exit = process.waitFor();
        stdout.get(30, TimeUnit.SECONDS);
        stderr.get(30, TimeUnit.SECONDS);
        trace("direct Gradle Java exited with " + exit);
        return new ProcessResult(exit);
      } finally {
        pool.shutdownNow();
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      throw new RuntimeException("interrupted while running the sandboxed Gradle process", error);
    } catch (Exception error) {
      trace("direct Gradle Java launch failed: " + error);
      throw new RuntimeException("failed to run the sandboxed Gradle process", error);
    }
  }

  public static ProcessResult run$default(
      ProcessRunner self,
      List<String> command,
      Path cwd,
      Map<String, String> env,
      Function1<? super String, Unit> onStdout,
      Function1<? super String, Unit> onStderr,
      int mask,
      Object marker) {
    if (marker != null) {
      throw new UnsupportedOperationException("super calls with default arguments are unsupported");
    }
    if ((mask & 4) != 0) env = Collections.emptyMap();
    if ((mask & 8) != 0) onStdout = value -> Unit.INSTANCE;
    if ((mask & 16) != 0) onStderr = value -> Unit.INSTANCE;
    return self.run(command, cwd, env, onStdout, onStderr);
  }

  private static List<String> rewriteGradleCommand(List<String> command) {
    if (command.isEmpty()
        || !"gradle".equals(command.get(0))
        || !"1".equals(System.getenv("SNIFF_INTERNAL_GRADLE_LAUNCHER"))) {
      return command;
    }
    normalizeInitScript(command);
    String javaHome = requiredEnvironment("JAVA_HOME");
    String classpath = requiredEnvironment("SNIFF_GRADLE_CLASSPATH");
    String mainClass = requiredEnvironment("SNIFF_GRADLE_MAIN_CLASS");
    if (!mainClass.equals("org.gradle.wrapper.GradleWrapperMain")
        && !mainClass.equals("org.gradle.launcher.GradleMain")) {
      throw new IllegalStateException("unsupported Gradle main class");
    }
    String project = requiredEnvironment("SNIFF_GRADLE_PROJECT");
    String projectCache = requiredEnvironment("SNIFF_GRADLE_PROJECT_CACHE");
    String gradleUserHome = requiredEnvironment("SNIFF_GRADLE_USER_HOME");
    String temporaryDirectory = requiredEnvironment("SNIFF_GRADLE_TEMP");
    verifyWritableDirectory(Path.of(gradleUserHome, ".tmp"), "Gradle user-home temp");
    verifyWritableDirectory(Path.of(temporaryDirectory), "JVM temp");
    String javaOptions = requiredEnvironment("JAVA_OPTS");
    int agentSeparator = javaOptions.lastIndexOf(" -javaagent:");
    if (agentSeparator < 0 || !javaOptions.substring(0, agentSeparator).equals(BASE_JVM_OPTIONS)) {
      throw new IllegalStateException("unexpected Gradle JAVA_OPTS contract");
    }
    String agent = javaOptions.substring(agentSeparator + " -javaagent:".length());
    if (agent.isEmpty()) throw new IllegalStateException("missing Gradle instrumentation agent");

    List<String> rewritten = new ArrayList<>();
    rewritten.add(Path.of(javaHome, "bin", "java.exe").toString());
    Collections.addAll(rewritten, BASE_JVM_OPTIONS.split(" "));
    rewritten.add("-javaagent:" + agent);
    rewritten.add("-Dorg.gradle.appname=gradle");
    rewritten.add("-Dgradle.user.home=" + gradleUserHome);
    rewritten.add("-Djava.io.tmpdir=" + temporaryDirectory);
    rewritten.add("-classpath");
    rewritten.add(classpath);
    rewritten.add(mainClass);
    rewritten.add("-p");
    rewritten.add(project);
    rewritten.add("--gradle-user-home");
    rewritten.add(gradleUserHome);
    rewritten.add("--project-cache-dir");
    rewritten.add(projectCache);
    rewritten.add("--no-watch-fs");
    rewritten.add("--stacktrace");
    if ("1".equals(System.getenv("SNIFF_GRADLE_OFFLINE"))) {
      rewritten.add("--offline");
    }
    rewritten.addAll(command.subList(1, command.size()));
    trace("rewrote Gradle to one direct Java child");
    return rewritten;
  }

  private static void verifyWritableDirectory(Path directory, String label) {
    try {
      Files.createDirectories(directory);
      Path probe = Files.createTempFile(directory, "sniff-gradle-probe-", ".tmp");
      Files.delete(probe);
      trace(label + " is writable: " + directory);
    } catch (Exception error) {
      trace(label + " is not writable: " + directory + ": " + error);
      throw new IllegalStateException(label + " is not writable inside the Sniff sandbox: " + directory, error);
    }
  }

  private static void normalizeInitScript(List<String> command) {
    for (int index = 0; index < command.size(); index++) {
      String argument = command.get(index);
      if (!argument.equals("--init-script") && !argument.equals("-I")) continue;
      if (index + 1 >= command.size()) throw new IllegalStateException("missing Gradle init script");
      Path script = Path.of(command.get(index + 1));
      try {
        Files.writeString(
            script,
            Files.readString(script, StandardCharsets.UTF_8).replace('\\', '/'),
            StandardCharsets.UTF_8);
      } catch (Exception error) {
        throw new RuntimeException("failed to normalize the scip-java init script", error);
      }
      return;
    }
  }

  private static String requiredEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) throw new IllegalStateException("missing " + name);
    return value;
  }

  private static void drain(InputStream input, Function1<? super String, Unit> sink) {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) sink.invoke(line);
    } catch (Exception error) {
      throw new RuntimeException("failed to read sandboxed Gradle output", error);
    }
  }

  private static void trace(String message) {
    String destination = System.getenv("SNIFF_GRADLE_TRACE");
    if (destination == null || destination.isEmpty()) return;
    try {
      Files.writeString(
          Path.of(destination),
          message + System.lineSeparator(),
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.APPEND);
    } catch (Exception ignored) {
      // Debug tracing must not alter indexing behavior.
    }
  }
}
"#;

#[cfg(windows)]
const WINDOWS_GRADLE_TEMP_FILES: &str = r#"package org.gradle.api.internal.file.temp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class TempFiles {
  private TempFiles() {}

  static File createTempFile(String prefix, String suffix, File directory) throws IOException {
    if (directory == null) {
      throw new NullPointerException("The `directory` argument must not be null");
    }
    if (prefix == null) prefix = "gradle-";
    if (prefix.length() <= 3) prefix = "tmp-" + prefix;
    return Files.createTempFile(directory.toPath(), prefix, suffix).toFile();
  }
}
"#;

#[cfg(windows)]
const WINDOWS_SCIP_JAVA_LAUNCHER_REPACKER: &str = r#"
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class LauncherRepacker {
  private LauncherRepacker() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      throw new IllegalArgumentException(
          "expected launcher, replacement, output, and target entry arguments");
    }
    Path launcher = Path.of(args[0]);
    Path replacement = Path.of(args[1]);
    Path output = Path.of(args[2]);
    String target = args[3];
    byte[] replacementBytes = Files.readAllBytes(replacement);
    CRC32 replacementCrc = new CRC32();
    replacementCrc.update(replacementBytes);
    int replacements = 0;
    try (ZipFile input = new ZipFile(launcher.toFile());
        ZipOutputStream rebuilt = new ZipOutputStream(Files.newOutputStream(output))) {
      Enumeration<? extends ZipEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        ZipEntry source = entries.nextElement();
        boolean replacing = source.getName().equals(target);
        ZipEntry destination = replacing ? replacementEntry(source) : new ZipEntry(source);
        if (replacing && source.getMethod() == ZipEntry.STORED) {
          destination.setSize(replacementBytes.length);
          destination.setCompressedSize(replacementBytes.length);
          destination.setCrc(replacementCrc.getValue());
        }
        rebuilt.putNextEntry(destination);
        if (replacing) {
          rebuilt.write(replacementBytes);
          replacements++;
        } else if (!source.isDirectory()) {
          try (InputStream contents = input.getInputStream(source)) {
            contents.transferTo(rebuilt);
          }
        }
        rebuilt.closeEntry();
      }
    }
    if (replacements != 1) {
      Files.deleteIfExists(output);
      throw new IllegalStateException(
          "expected exactly one " + target + " entry, found " + replacements);
    }
  }

  private static ZipEntry replacementEntry(ZipEntry source) {
    ZipEntry destination = new ZipEntry(source.getName());
    destination.setMethod(source.getMethod());
    if (source.getComment() != null) destination.setComment(source.getComment());
    if (source.getExtra() != null) destination.setExtra(source.getExtra());
    if (source.getLastModifiedTime() != null) {
      destination.setLastModifiedTime(source.getLastModifiedTime());
    }
    if (source.getLastAccessTime() != null) {
      destination.setLastAccessTime(source.getLastAccessTime());
    }
    if (source.getCreationTime() != null) {
      destination.setCreationTime(source.getCreationTime());
    }
    return destination;
  }
}
"#;

#[cfg(windows)]
fn patch_scip_java_windows(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
    let entrypoint = root.join(spec.entrypoint_relative_path());
    let patch_root = std::env::temp_dir().join(format!(
        "sniff-scip-java-patch-{}-{}",
        std::process::id(),
        unique_patch_suffix()
    ));
    fs::create_dir_all(&patch_root).map_err(|error| {
        format!(
            "failed to create temporary scip-java patch directory {}: {error}",
            patch_root.display()
        )
    })?;
    let result: Result<(), String> = (|| {
        let launcher_root = patch_root.join("launcher");
        fs::create_dir_all(&launcher_root).map_err(|error| {
            format!(
                "failed to create scip-java launcher extraction directory {}: {error}",
                launcher_root.display()
            )
        })?;
        let writer_source = patch_root.join("ScipWriter.java");
        fs::write(&writer_source, WINDOWS_SCIP_JAVA_WRITER).map_err(|error| {
            format!("failed to write the Windows scip-java compatibility source: {error}")
        })?;
        let runner_source = patch_root.join("ProcessRunner.java");
        fs::write(&runner_source, WINDOWS_SCIP_JAVA_PROCESS_RUNNER).map_err(|error| {
            format!("failed to write the Windows scip-java process patch source: {error}")
        })?;
        let gradle_temp_source = patch_root.join("TempFiles.java");
        fs::write(&gradle_temp_source, WINDOWS_GRADLE_TEMP_FILES).map_err(|error| {
            format!("failed to write the Windows Gradle temp compatibility source: {error}")
        })?;
        let repacker_source = patch_root.join("LauncherRepacker.java");
        fs::write(&repacker_source, WINDOWS_SCIP_JAVA_LAUNCHER_REPACKER).map_err(|error| {
            format!("failed to write the Windows scip-java launcher repacker source: {error}")
        })?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&launcher_root)
                .arg("xf")
                .arg(&entrypoint)
                .args([
                    "coursier/bootstrap/launcher/jars/scip-aggregator-0.13.1.jar",
                    "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar",
                    "coursier/bootstrap/launcher/jars/scip-java-bindings-0.9.0.jar",
                    "coursier/bootstrap/launcher/jars/protobuf-java-4.34.2.jar",
                    "coursier/bootstrap/launcher/jars/kotlin-stdlib-2.3.20.jar",
                ]),
            "extract scip-java Windows compatibility patch dependencies",
        )?;
        let jars = launcher_root.join("coursier/bootstrap/launcher/jars");
        let aggregator = jars.join("scip-aggregator-0.13.1.jar");
        let scip_java = jars.join("scip-java-0.13.1.jar");
        let bindings = jars.join("scip-java-bindings-0.9.0.jar");
        let protobuf = jars.join("protobuf-java-4.34.2.jar");
        let kotlin_stdlib = jars.join("kotlin-stdlib-2.3.20.jar");
        for path in [
            &aggregator,
            &scip_java,
            &bindings,
            &protobuf,
            &kotlin_stdlib,
        ] {
            if !path.is_file() {
                return Err(format!(
                    "scip-java runtime is missing patch dependency {}",
                    path.display()
                ));
            }
        }

        let classes = patch_root.join("classes");
        fs::create_dir_all(&classes).map_err(|error| {
            format!(
                "failed to create scip-java patch classes directory {}: {error}",
                classes.display()
            )
        })?;
        let classpath = std::env::join_paths([
            &aggregator,
            &scip_java,
            &bindings,
            &protobuf,
            &kotlin_stdlib,
        ])
        .map_err(|error| format!("failed to build scip-java patch classpath: {error}"))?;
        run_patch_tool(
            std::process::Command::new("javac")
                .current_dir(&patch_root)
                .arg("-cp")
                .arg(&classpath)
                .arg("-d")
                .arg(&classes)
                .arg(&writer_source)
                .arg(&runner_source)
                .arg(&gradle_temp_source)
                .arg(&repacker_source),
            "compile scip-java Windows compatibility patch",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .arg("uf")
                .arg(&scip_java)
                .arg("-C")
                .arg(&classes)
                .arg("org/scip_code/scip_java/buildtools/ProcessRunner.class"),
            "patch scip-java Windows process runner",
        )?;
        let rebuilt_zip = patch_root.join("scip-java-rebuilt.zip");
        run_patch_tool(
            std::process::Command::new("java")
                .arg("-cp")
                .arg(&classes)
                .arg("LauncherRepacker")
                .arg(&entrypoint)
                .arg(&scip_java)
                .arg(&rebuilt_zip)
                .arg("coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar"),
            "stream-rebuild patched scip-java launcher",
        )?;
        install_rebuilt_zip_preserving_prefix(
            &entrypoint,
            &rebuilt_zip,
            &[
                "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar",
                "coursier/bootstrap/launcher/ResourcesLauncher.class",
                "coursier/bootstrap/launcher/y.class",
                "coursier/bootstrap/launcher/Y.class",
            ],
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&classes)
                .arg("xf")
                .arg(&aggregator)
                .arg("org/scip_code/scip_java/aggregator/ScipOutputStream.class"),
            "extract scip-java Windows compatibility runtime class",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&classes)
                .arg("xf")
                .arg(&aggregator)
                .arg("org/scip_code/scip_java/aggregator/ScipAggregatorOptions.class"),
            "extract scip-java Windows aggregator options class",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&classes)
                .arg("xf")
                .arg(&bindings)
                .arg("org/scip_code/scip"),
            "extract scip-java Windows compatibility SCIP bindings",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&classes)
                .arg("xf")
                .arg(&protobuf)
                .arg("com/google/protobuf"),
            "extract scip-java Windows compatibility protobuf runtime",
        )?;
        let patch_dir = root.join("bin/scip-java-v0.13.1-patch");
        let patch_package = patch_dir.join("org/scip_code/scip_java/aggregator");
        let gradle_patch_package = patch_dir.join("sniff-gradle-patch");
        let scip_package = patch_dir.join("org/scip_code/scip");
        let protobuf_package = patch_dir.join("com/google/protobuf");
        if patch_package.exists() {
            return Err(format!(
                "scip-java compatibility patch directory already exists: {}",
                patch_dir.display()
            ));
        }
        fs::create_dir_all(&patch_package)
            .map_err(|error| format!("failed to create scip-java patch directory: {error}"))?;
        fs::create_dir_all(&gradle_patch_package)
            .map_err(|error| format!("failed to create Gradle temp patch directory: {error}"))?;
        fs::create_dir_all(&scip_package)
            .map_err(|error| format!("failed to create scip-java bindings directory: {error}"))?;
        for class_name in [
            "ScipWriter.class",
            "ScipOutputStream.class",
            "ScipAggregatorOptions.class",
        ] {
            let source_class = classes
                .join("org/scip_code/scip_java/aggregator")
                .join(class_name);
            let patch_class = patch_package.join(class_name);
            if !source_class.is_file() {
                return Err(format!(
                    "scip-java compatibility class is missing: {}",
                    source_class.display()
                ));
            }
            fs::copy(&source_class, &patch_class).map_err(|error| {
                format!(
                    "failed to write scip-java compatibility class {}: {error}",
                    patch_class.display()
                )
            })?;
        }
        let gradle_temp_class = classes.join("org/gradle/api/internal/file/temp/TempFiles.class");
        if !gradle_temp_class.is_file() {
            return Err(format!(
                "Gradle temp compatibility class is missing: {}",
                gradle_temp_class.display()
            ));
        }
        fs::copy(
            &gradle_temp_class,
            gradle_patch_package.join("TempFiles.class"),
        )
        .map_err(|error| format!("failed to install Gradle temp compatibility class: {error}"))?;
        copy_patch_tree(
            &classes.join("org/scip_code/scip"),
            &scip_package,
            "scip-java bindings",
        )?;
        copy_patch_tree(
            &classes.join("com/google/protobuf"),
            &protobuf_package,
            "protobuf runtime",
        )?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&patch_root);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.to_string()),
        (Err(patch_error), Err(cleanup_error)) => Err(format!(
            "{patch_error}; additionally failed to remove patch directory {}: {cleanup_error}",
            patch_root.display()
        )),
    }
}

#[cfg(windows)]
fn install_rebuilt_zip_preserving_prefix(
    launcher_path: &Path,
    rebuilt_zip_path: &Path,
    required_entries: &[&str],
) -> Result<(), String> {
    const MAX_EXECUTABLE_PREFIX_BYTES: usize = 1024 * 1024;
    const LOCAL_ZIP_HEADER: &[u8; 4] = b"PK\x03\x04";

    let launcher_bytes = fs::read(launcher_path).map_err(|error| {
        format!(
            "failed to read scip-java launcher {} for rebuilding: {error}",
            launcher_path.display()
        )
    })?;
    if !launcher_bytes.starts_with(b"#!") {
        return Err(format!(
            "scip-java launcher {} does not have the expected executable script prefix",
            launcher_path.display()
        ));
    }
    let search_end = launcher_bytes.len().min(MAX_EXECUTABLE_PREFIX_BYTES);
    let prefix_len = launcher_bytes[..search_end]
        .windows(LOCAL_ZIP_HEADER.len())
        .position(|bytes| bytes == LOCAL_ZIP_HEADER)
        .ok_or_else(|| {
            format!(
                "scip-java launcher {} has no ZIP header within its first {} bytes",
                launcher_path.display(),
                MAX_EXECUTABLE_PREFIX_BYTES
            )
        })?;
    if prefix_len == 0 {
        return Err(format!(
            "scip-java launcher {} has no executable prefix to preserve",
            launcher_path.display()
        ));
    }
    let input = File::open(rebuilt_zip_path).map_err(|error| {
        format!(
            "failed to open rebuilt scip-java ZIP {}: {error}",
            rebuilt_zip_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(input)
        .map_err(|error| format!("failed to parse rebuilt scip-java ZIP: {error}"))?;
    if archive.offset() != 0 {
        return Err(format!(
            "rebuilt scip-java launcher {} is not a plain ZIP archive",
            rebuilt_zip_path.display()
        ));
    }
    let archive_comment = archive.comment().to_vec().into_boxed_slice();
    let output_path = launcher_path.with_extension("sniff-rebuilt");
    if output_path.exists() {
        fs::remove_file(&output_path).map_err(|error| {
            format!(
                "failed to clear stale scip-java rebuild output {}: {error}",
                output_path.display()
            )
        })?;
    }
    let mut output = File::create(&output_path).map_err(|error| {
        format!(
            "failed to create scip-java rebuild output {}: {error}",
            output_path.display()
        )
    })?;
    output
        .write_all(&launcher_bytes[..prefix_len])
        .map_err(|error| format!("failed to preserve scip-java executable prefix: {error}"))?;
    let mut rebuilt = zip::ZipWriter::new(output);
    rebuilt.set_raw_comment(archive_comment);
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            format!("failed to inspect rebuilt scip-java ZIP entry {index}: {error}")
        })?;
        rebuilt.raw_copy_file(entry).map_err(|error| {
            format!("failed to preserve rebuilt scip-java ZIP entry {index}: {error}")
        })?;
    }
    let rebuilt_file = rebuilt
        .finish()
        .map_err(|error| format!("failed to finish rebuilt scip-java launcher: {error}"))?;
    rebuilt_file
        .sync_all()
        .map_err(|error| format!("failed to sync rebuilt scip-java launcher: {error}"))?;
    drop(archive);

    let assembled = fs::read(&output_path)
        .map_err(|error| format!("failed to validate rebuilt scip-java launcher: {error}"))?;
    if !assembled.starts_with(&launcher_bytes[..prefix_len])
        || assembled.get(prefix_len..prefix_len + LOCAL_ZIP_HEADER.len()) != Some(LOCAL_ZIP_HEADER)
    {
        return Err(
            "patched scip-java launcher did not preserve its executable prefix".to_string(),
        );
    }
    let mut validation = File::open(&output_path)
        .map_err(|error| error.to_string())
        .and_then(|file| ZipArchive::new(file).map_err(|error| error.to_string()))?;
    for required_entry in required_entries {
        let entry = validation.by_name(required_entry).map_err(|error| {
            format!(
                "rebuilt scip-java launcher is missing required entry {required_entry}: {error}"
            )
        })?;
        if required_entry.ends_with(".jar") && entry.compression() != zip::CompressionMethod::Stored
        {
            return Err(format!(
                "rebuilt scip-java nested runtime {required_entry} must remain stored without compression"
            ));
        }
    }
    validation
        .by_name("META-INF/MANIFEST.MF")
        .map_err(|error| format!("rebuilt scip-java launcher is missing its manifest: {error}"))?;
    drop(validation);
    fs::copy(&output_path, launcher_path).map_err(|error| {
        format!(
            "failed to install patched scip-java launcher {}: {error}",
            launcher_path.display()
        )
    })?;
    fs::remove_file(&output_path).map_err(|error| {
        format!(
            "failed to remove scip-java repack output {}: {error}",
            output_path.display()
        )
    })?;
    Ok(())
}

#[cfg(windows)]
fn copy_patch_tree(source: &Path, target: &Path, label: &str) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "extracted {label} directory is missing: {}",
            source.display()
        ));
    }
    fs::create_dir_all(target).map_err(|error| {
        format!(
            "failed to create {label} directory {}: {error}",
            target.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "failed to read {label} directory {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate {label} directory {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_patch_tree(&source_path, &target_path, label)?;
        } else if source_path.is_file() {
            fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "failed to write {label} class {}: {error}",
                    target_path.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn run_patch_tool(command: &mut std::process::Command, label: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("{label} could not start: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label} failed with {}: {}",
            output.status,
            compact_output(&output.stderr)
        ))
    }
}

#[cfg(windows)]
fn unique_patch_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

async fn install_npm(spec: PinnedIndexer, root: &Path, package: &str) -> Result<(), String> {
    let package_spec = format!("{package}@{}", spec.version);
    let npm = executable_name("npm");
    let mut view_command = Command::new(&npm);
    view_command
        .arg("view")
        .arg(&package_spec)
        .arg("dist.integrity")
        .arg("--json");
    let view = run_command(&mut view_command, "npm package integrity lookup").await?;
    let actual = parse_json_string(&view, "npm integrity")?;
    let expected = format!(
        "sha512-{}",
        match spec.source {
            IndexerInstallSource::Npm {
                integrity_sha512, ..
            } => integrity_sha512,
            _ => unreachable!(),
        }
    );
    if actual.trim() != expected {
        return Err(format!(
            "{} npm integrity mismatch; expected {}, received {}",
            spec.display_name,
            expected,
            actual.trim()
        ));
    }
    let mut install_command = Command::new(&npm);
    install_command
        .arg("install")
        .arg("--prefix")
        .arg(root)
        .args([
            "--ignore-scripts",
            "--no-bin-links",
            "--no-package-lock",
            "--omit=dev",
        ])
        .arg(&package_spec);
    run_command(&mut install_command, "npm package installation")
        .await
        .map(|_| ())
}

async fn install_download(
    spec: PinnedIndexer,
    root: &Path,
    download: crate::semantic_indexer_manifest::IndexerDownload,
) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .get(download.url)
        .send()
        .await
        .map_err(|error| format!("failed to download {}: {error}", spec.display_name))?
        .error_for_status()
        .map_err(|error| format!("download failed for {}: {error}", spec.display_name))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_DOWNLOAD_BYTES)
    {
        return Err(format!(
            "{} download exceeds {} bytes",
            spec.display_name, MAX_DOWNLOAD_BYTES
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("failed to read {} download: {error}", spec.display_name))?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "{} download exceeds {} bytes",
            spec.display_name, MAX_DOWNLOAD_BYTES
        ));
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != download.sha256 {
        return Err(format!(
            "{} download checksum mismatch; expected {}, received {}",
            spec.display_name, download.sha256, actual
        ));
    }
    match download.archive {
        DownloadArchive::Raw => write_binary(root, &spec.entrypoint_relative_path(), &bytes),
        DownloadArchive::Gzip => {
            let mut decoder = GzDecoder::new(Cursor::new(bytes));
            let mut unpacked = Vec::new();
            decoder
                .read_to_end(&mut unpacked)
                .map_err(|error| format!("failed to unpack {}: {error}", spec.display_name))?;
            write_binary(root, &spec.entrypoint_relative_path(), &unpacked)
        }
        DownloadArchive::Zip => unpack_zip(root, spec, &bytes),
    }
}

fn unpack_zip(root: &Path, spec: PinnedIndexer, bytes: &[u8]) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("failed to open {} archive: {error}", spec.display_name))?;
    let entrypoint_relative = spec.entrypoint_relative_path();
    let expected_name = entrypoint_relative
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has an invalid entrypoint name", spec.display_name))?;
    let mut found = false;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect {} archive: {error}", spec.display_name))?;
        if entry.is_dir() {
            continue;
        }
        let name = Path::new(entry.name());
        let file_name = name
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "{} archive contains an invalid entry name",
                    spec.display_name
                )
            })?;
        if name.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(format!(
                "{} archive contains an unsafe entry {}",
                spec.display_name,
                entry.name()
            ));
        }
        if file_name != expected_name {
            continue;
        }
        let mut unpacked = Vec::new();
        entry
            .read_to_end(&mut unpacked)
            .map_err(|error| format!("failed to unpack {}: {error}", spec.display_name))?;
        write_binary(root, &entrypoint_relative, &unpacked)?;
        found = true;
    }
    if found {
        Ok(())
    } else {
        Err(format!(
            "{} archive did not contain its entrypoint",
            spec.display_name
        ))
    }
}

fn write_binary(root: &Path, relative: &Path, bytes: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("binary path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create binary directory {}: {error}",
            parent.display()
        )
    })?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(unix)]
    options.mode(0o755);
    let mut file = options
        .open(&path)
        .map_err(|error| format!("failed to write binary {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to sync binary {}: {error}", path.display()))
}

async fn run_command(command: &mut Command, label: &str) -> Result<Vec<u8>, String> {
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{label} timed out after {} seconds",
                COMMAND_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("{label} could not start: {error}"))?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "{label} failed with {}; output: {}",
            output.status,
            compact_output(&combined)
        ))
    }
}

async fn run_json_command(command: &mut Command, label: &str) -> Result<Vec<u8>, String> {
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{label} timed out after {} seconds",
                COMMAND_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("{label} could not start: {error}"))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    Err(format!(
        "{label} failed with {}; output: {}",
        output.status,
        compact_output(&combined)
    ))
}

fn parse_json_string(bytes: &[u8], label: &str) -> Result<String, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("{label} returned invalid JSON: {error}"))?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{label} did not return a JSON string"))
}

fn compact_output(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() > 400 {
        format!("{}...", &compact[..400])
    } else {
        compact
    }
}

fn executable_name(name: &str) -> OsString {
    if cfg!(windows) {
        OsString::from(format!("{name}.cmd"))
    } else {
        OsString::from(name)
    }
}

#[cfg(test)]
#[path = "tests/semantic_indexer_installer.rs"]
mod tests;
