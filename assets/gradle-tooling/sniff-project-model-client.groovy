import groovy.json.JsonOutput
import org.gradle.tooling.GradleConnector

interface SniffGradleProjectModel {
    String getProjectPath()
    String getProjectName()
    String getGroupName()
    String getProjectVersion()
    String getProjectDirectory()
    String getBuildFile()
    boolean getBuildFileExists()
    List<String> getProviderKinds()
    List<String> getProductionSourceFiles()
    List<? extends SniffGradleProducerTaskModel> getProducerTasks()
}

interface SniffGradleProducerTaskModel {
    String getTaskPath()
    String getTaskType()
    List<String> getOutputFiles()
    List<String> getProductionSourceFiles()
}

interface SniffGradleBuildModel {
    String getContract()
    String getGradleVersion()
    String getSettingsDirectory()
    List<? extends SniffGradleProjectModel> getProjects()
}

if (args.length != 4) {
    throw new IllegalArgumentException("expected project, Gradle home, private user home and init script")
}

File projectDirectory = new File(args[0]).canonicalFile
File gradleHome = new File(args[1]).canonicalFile
File gradleUserHome = new File(args[2]).canonicalFile
File initScript = new File(args[3]).canonicalFile
File projectCache = new File(gradleUserHome, "project-cache")
if (!projectCache.mkdirs() && !projectCache.isDirectory()) {
    throw new IOException("failed to create private Gradle project cache")
}
def connector = GradleConnector.newConnector()
    .forProjectDirectory(projectDirectory)
    .useInstallation(gradleHome)
    .useGradleUserHomeDir(gradleUserHome)
def connection = connector.connect()
try {
    def builder = connection.model(SniffGradleBuildModel)
        .setJvmArguments(
            "-Xms64m",
            "-Xmx768m",
            "-XX:MaxMetaspaceSize=256m",
            "-XX:ReservedCodeCacheSize=128m",
            "-XX:+UseSerialGC",
        )
        .withArguments(
            "--offline",
            "--no-build-cache",
            "--no-configuration-cache",
            "--project-cache-dir",
            projectCache.absolutePath,
            "--init-script",
            initScript.absolutePath,
        )
        .setStandardOutput(System.err)
        .setStandardError(System.err)
    SniffGradleBuildModel model = builder.get()
    def payload = [
        contract: model.contract,
        tooling_api_version: "8.8",
        gradle_version: model.gradleVersion,
        settings_directory: model.settingsDirectory,
        projects: model.projects.collect { project -> [
            project_path: project.projectPath,
            project_name: project.projectName,
            group_name: project.groupName,
            project_version: project.projectVersion,
            project_directory: project.projectDirectory,
            build_file: project.buildFile,
            build_file_exists: project.buildFileExists,
            provider_kinds: project.providerKinds,
            production_source_files: project.productionSourceFiles,
            producer_tasks: project.producerTasks.collect { task -> [
                task_path: task.taskPath,
                task_type: task.taskType,
                output_files: task.outputFiles,
                production_source_files: task.productionSourceFiles,
            ] },
        ] },
    ]
    print(JsonOutput.toJson(payload))
} finally {
    connection.close()
    connector.disconnect()
}
