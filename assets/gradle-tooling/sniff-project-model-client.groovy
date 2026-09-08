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
    List<String> getComponentNames()
    List<? extends SniffGradlePublicationModel> getPublications()
    List<? extends SniffKotlinSourceSetModel> getKotlinSourceSets()
    List<? extends SniffKotlinTargetModel> getKotlinTargets()
}

interface SniffGradlePublicationModel {
    String getName()
    String getPublicationType()
    String getGroupId()
    String getArtifactId()
    String getVersion()
}

interface SniffKotlinSourceSetModel {
    String getName()
    List<String> getSourceFiles()
    List<String> getDependsOnSourceSets()
}

interface SniffKotlinCompilationModel {
    String getName()
    String getDefaultSourceSet()
    List<String> getSourceSets()
}

interface SniffKotlinTargetModel {
    String getName()
    String getPlatformType()
    boolean getPublishable()
    List<String> getComponentNames()
    List<? extends SniffKotlinCompilationModel> getCompilations()
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
            component_names: project.componentNames,
            publications: project.publications.collect { publication -> [
                name: publication.name,
                publication_type: publication.publicationType,
                group_id: publication.groupId,
                artifact_id: publication.artifactId,
                version: publication.version,
            ] },
            kotlin_source_sets: project.kotlinSourceSets.collect { sourceSet -> [
                name: sourceSet.name,
                source_files: sourceSet.sourceFiles,
                depends_on_source_sets: sourceSet.dependsOnSourceSets,
            ] },
            kotlin_targets: project.kotlinTargets.collect { target -> [
                name: target.name,
                platform_type: target.platformType,
                publishable: target.publishable,
                component_names: target.componentNames,
                compilations: target.compilations.collect { compilation -> [
                    name: compilation.name,
                    default_source_set: compilation.defaultSourceSet,
                    source_sets: compilation.sourceSets,
                ] },
            ] },
        ] },
    ]
    print(JsonOutput.toJson(payload))
} finally {
    connection.close()
    connector.disconnect()
}
