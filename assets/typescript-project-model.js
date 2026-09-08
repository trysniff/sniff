'use strict';

const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = 1;
const SOURCE_EXTENSIONS = [
  '.cjs',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.mts',
  '.ts',
  '.tsx',
];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function readJson(file, label) {
  let bytes;
  try {
    bytes = fs.readFileSync(file);
  } catch (error) {
    fail(`failed to read ${label}: ${error.message}`);
  }
  if (bytes.length > 16 * 1024 * 1024) {
    fail(`${label} exceeds 16777216 bytes`);
  }
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`failed to parse ${label}: ${error.message}`);
  }
}

if (process.argv.length !== 4) {
  fail('usage: node typescript-project-model.js <typescript.js> <input.json>');
}

const typescriptPath = path.resolve(process.argv[2]);
const inputPath = path.resolve(process.argv[3]);
const input = readJson(inputPath, 'project-model input');
const root = fs.realpathSync(process.cwd());
const ts = require(typescriptPath);

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function safeInputPath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || path.isAbsolute(value)) {
    fail(`${label} is not a canonical repository path`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    fail(`${label} is not a canonical repository path`);
  }
  return value;
}

function repositoryPath(absolute, label) {
  const resolved = path.resolve(absolute);
  const relative = path.relative(root, resolved);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(`${label} escaped the repository root: ${resolved}`);
  }
  return relative.split(path.sep).join('/');
}

function normalizeCompilerValue(value, label) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    if (!path.isAbsolute(value)) {
      return value;
    }
    return `<repo>/${repositoryPath(value, label)}`;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => normalizeCompilerValue(item, `${label}[${index}]`));
  }
  if (typeof value === 'object') {
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      const item = value[key];
      if (item !== undefined) {
        normalized[key] = normalizeCompilerValue(item, `${label}.${key}`);
      }
    }
    return normalized;
  }
  fail(`${label} contains unsupported compiler data`);
}

function diagnosticRecord(diagnostic) {
  const record = {
    category: ts.DiagnosticCategory[diagnostic.category].toLowerCase(),
    code: diagnostic.code,
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
  };
  if (diagnostic.file) {
    record.file = repositoryPath(diagnostic.file.fileName, 'diagnostic file');
  }
  if (diagnostic.start !== undefined) {
    record.start = diagnostic.start;
  }
  if (diagnostic.length !== undefined) {
    record.length = diagnostic.length;
  }
  return record;
}

function isSourceFile(repositoryPathValue) {
  const lower = repositoryPathValue.toLowerCase();
  return SOURCE_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

if (!input || input.schemaVersion !== SCHEMA_VERSION || !Array.isArray(input.configs) || !Array.isArray(input.sourceFiles)) {
  fail('project-model input contract changed');
}

const inputConfigs = sortedUnique(input.configs.map((value) => safeInputPath(value, 'config path')));
const sourceFiles = sortedUnique(input.sourceFiles.map((value) => safeInputPath(value, 'source path')));
if (sourceFiles.some((value) => !isSourceFile(value))) {
  fail('project-model input contains a non-TypeScript/JavaScript source');
}
const sourceFileSet = new Set(sourceFiles);

const projects = new Map();
const queue = inputConfigs.slice();

function parseProject(configRepositoryPath) {
  const configAbsolute = path.join(root, ...configRepositoryPath.split('/'));
  const configReads = new Set();
  const diagnostics = [];
  const host = {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic(diagnostic) {
      diagnostics.push(diagnostic);
    },
    readFile(fileName) {
      const resolved = path.resolve(fileName);
      if (resolved.toLowerCase().endsWith('.json')) {
        configReads.add(repositoryPath(resolved, 'compiler configuration read'));
      }
      return ts.sys.readFile(fileName);
    },
  };
  const parsed = ts.getParsedCommandLineOfConfigFile(configAbsolute, {}, host);
  if (!parsed) {
    fail(`TypeScript did not return a parsed project for ${configRepositoryPath}`);
  }
  diagnostics.push(...parsed.errors);
  const references = sortedUnique((parsed.projectReferences || []).map((reference) => {
    return repositoryPath(ts.resolveProjectReferencePath(reference), 'project reference');
  }));
  const selected = sortedUnique(parsed.fileNames
    .map((fileName) => repositoryPath(fileName, 'compiler-selected source'))
    .filter((value) => isSourceFile(value) && sourceFileSet.has(value)));
  return {
    configPath: configRepositoryPath,
    configReads: sortedUnique(configReads),
    diagnostics: diagnostics.map(diagnosticRecord).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    effectiveOptions: normalizeCompilerValue(parsed.options, 'compiler options'),
    references,
    selectedSourceFiles: selected,
  };
}

while (queue.length > 0) {
  const config = queue.shift();
  if (projects.has(config)) {
    continue;
  }
  const project = parseProject(config);
  projects.set(config, project);
  for (const reference of project.references) {
    if (!projects.has(reference)) {
      queue.push(reference);
    }
  }
  queue.sort();
}

function closureFor(rootConfig) {
  const closure = new Set();
  const pending = [rootConfig];
  while (pending.length > 0) {
    const current = pending.pop();
    if (closure.has(current)) {
      continue;
    }
    closure.add(current);
    const project = projects.get(current);
    if (!project) {
      fail(`project reference ${current} was not parsed`);
    }
    for (const reference of project.references) {
      pending.push(reference);
    }
  }
  return sortedUnique(closure);
}

let worlds;
if (projects.size === 0) {
  if (sourceFiles.length === 0) {
    worlds = [];
  } else {
    const hasTypeScript = sourceFiles.some((value) => value.endsWith('.ts') || value.endsWith('.tsx'));
    const synthetic = hasTypeScript ? {} : { compilerOptions: { allowJs: true } };
    const parsed = ts.parseJsonConfigFileContent(synthetic, ts.sys, root, undefined, path.join(root, 'tsconfig.json'));
    const selected = sortedUnique(parsed.fileNames
      .map((fileName) => repositoryPath(fileName, 'inferred compiler-selected source'))
      .filter((value) => isSourceFile(value) && sourceFileSet.has(value)));
    worlds = [{
      configClosure: [],
      diagnostics: parsed.errors.map(diagnosticRecord).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
      inferred: true,
      projects: [{
        configPath: null,
        configReads: [],
        diagnostics: [],
        effectiveOptions: normalizeCompilerValue(parsed.options, 'inferred compiler options'),
        references: [],
        selectedSourceFiles: selected,
      }],
      rootConfig: null,
      selectedSourceFiles: selected,
    }];
  }
} else {
  const referenced = new Set([...projects.values()].flatMap((project) => project.references));
  const extended = new Set([...projects.values()].flatMap((project) => {
    return project.configReads.filter((config) => config !== project.configPath && projects.has(config));
  }));
  const roots = [...projects.keys()]
    .filter((config) => !referenced.has(config) && !extended.has(config))
    .sort();
  if (roots.length === 0) {
    fail('TypeScript project-reference graph has no root project');
  }
  worlds = roots.map((rootConfig) => {
    const closure = closureFor(rootConfig);
    const worldProjects = closure.map((config) => projects.get(config));
    return {
      configClosure: closure,
      diagnostics: worldProjects.flatMap((project) => project.diagnostics),
      inferred: false,
      projects: worldProjects,
      rootConfig,
      selectedSourceFiles: sortedUnique(worldProjects.flatMap((project) => project.selectedSourceFiles)),
    };
  });
}

for (const world of worlds) {
  const selected = new Set(world.selectedSourceFiles);
  world.ignoredSourceFiles = sourceFiles.filter((source) => !selected.has(source));
}

process.stdout.write(`${JSON.stringify({
  schemaVersion: SCHEMA_VERSION,
  typescriptVersion: ts.version,
  worlds,
})}\n`);
