pub(super) const WINDOWS_SCIP_JAVA_WRITER: &str = r#"package org.scip_code.scip_java.aggregator;

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

pub(crate) const WINDOWS_SCIP_JAVA_PROCESS_RUNNER: &str = r#"package org.scip_code.scip_java.buildtools;

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
    isolateKotlinCompiler(command);
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

  private static void isolateKotlinCompiler(List<String> command) {
    String current = "-Pkotlin.compiler.execution.strategy=in-process";
    String isolated = "-Pkotlin.compiler.execution.strategy=out-of-process";
    int replacements = 0;
    for (int index = 0; index < command.size(); index++) {
      if (!command.get(index).startsWith("-Pkotlin.compiler.execution.strategy=")) continue;
      if (!command.get(index).equals(current)) {
        throw new IllegalStateException("unexpected Kotlin compiler execution strategy");
      }
      command.set(index, isolated);
      replacements++;
    }
    if (replacements != 1) {
      throw new IllegalStateException(
          "expected exactly one Kotlin compiler execution strategy, found " + replacements);
    }
    trace("isolated the Kotlin compiler in a bounded child process");
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

pub(crate) const WINDOWS_GRADLE_TEMP_FILES: &str = r#"package org.gradle.api.internal.file.temp;

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
