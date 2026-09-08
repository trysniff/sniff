import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const SCHEMA_VERSION = 1;
const require = createRequire(import.meta.url);

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

function digest(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function stableTrace(message) {
  const prefixes = new Set([
    root,
    root.split(path.sep).join('/'),
    root.split(path.sep).join('\\'),
  ]);
  let normalized = message;
  for (const prefix of [...prefixes].sort((left, right) => right.length - left.length)) {
    normalized = normalized.split(prefix).join('<repo>');
  }
  return normalized;
}

function safeRepositoryPath(value, label) {
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
  for (const mapping of input.pathMappings) {
    const source = path.resolve(root, ...mapping.runtimePrefix.split('/'));
    const relative = path.relative(source, resolved);
    if (relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))) {
      const suffix = relative === '' ? '' : relative.split(path.sep).join('/');
      if (suffix === '') {
        return mapping.repositoryPrefix;
      }
      return mapping.repositoryPrefix === '' ? suffix : `${mapping.repositoryPrefix}/${suffix}`;
    }
  }
  const relative = path.relative(root, resolved);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(`${label} escaped every committed path mapping: ${resolved}`);
  }
  return relative.split(path.sep).join('/');
}

function denormalizeCompilerValue(value, label) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    if (!value.startsWith('<repo>/')) {
      return value;
    }
    const repository = safeRepositoryPath(value.slice('<repo>/'.length), label);
    return path.join(root, ...repository.split('/'));
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => denormalizeCompilerValue(item, `${label}[${index}]`));
  }
  if (typeof value === 'object') {
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      normalized[key] = denormalizeCompilerValue(value[key], `${label}.${key}`);
    }
    return normalized;
  }
  fail(`${label} contains unsupported compiler data`);
}

function selectedCompilerExposure(traces, exposures, resolvedRepositoryPath) {
  if (resolvedRepositoryPath !== null) {
    const direct = exposures.filter(
      (exposure) => exposure.targetRepositoryPath === resolvedRepositoryPath,
    );
    if (direct.length > 0) {
      return {
        exposureId: direct.length === 1 ? direct[0].exposureId : null,
        ambiguous: direct.length !== 1,
      };
    }
  }
  let selectedTarget = null;
  let selectedAt = -1;
  for (const exposure of exposures) {
    const quoted = `'${exposure.packageRelativeTarget}'`;
    for (let index = 0; index < traces.length; index += 1) {
      const trace = traces[index];
      if ((trace.includes("with target '") || trace.includes("field '")) && trace.includes(quoted) && index >= selectedAt) {
        selectedTarget = exposure.packageRelativeTarget;
        selectedAt = index;
      }
    }
  }
  if (selectedTarget === null) {
    return { exposureId: null, ambiguous: false };
  }
  const matches = exposures.filter((exposure) => exposure.packageRelativeTarget === selectedTarget);
  return {
    exposureId: matches.length === 1 ? matches[0].exposureId : null,
    ambiguous: matches.length !== 1,
  };
}

function selectedRuntimeExposure(resolvedRepositoryPath, exposures) {
  const matches = exposures.filter((exposure) => exposure.targetRepositoryPath === resolvedRepositoryPath);
  return {
    exposureId: matches.length === 1 ? matches[0].exposureId : null,
    ambiguous: matches.length > 1,
  };
}

if (process.argv.length !== 4) {
  fail('usage: node node-consumer-profile.mjs <typescript.js> <input.json>');
}

const root = fs.realpathSync(process.cwd());
const typescriptPath = path.resolve(process.argv[2]);
const inputPath = path.resolve(process.argv[3]);
const input = readJson(inputPath, 'consumer-profile input');
const ts = require(typescriptPath);

if (!input || input.schemaVersion !== SCHEMA_VERSION || !Array.isArray(input.pathMappings) || !Array.isArray(input.exposures)) {
  fail('consumer-profile input contract changed');
}
if (input.mode !== 'import' && input.mode !== 'require') {
  fail('consumer-profile mode is invalid');
}
safeRepositoryPath(input.containingFile, 'consumer-profile containing file');
for (const mapping of input.pathMappings) {
  safeRepositoryPath(mapping.runtimePrefix, 'runtime mapping prefix');
  if (mapping.repositoryPrefix !== '') {
    safeRepositoryPath(mapping.repositoryPrefix, 'repository mapping prefix');
  }
}
for (const exposure of input.exposures) {
  safeRepositoryPath(exposure.targetRepositoryPath, 'consumer-profile target');
  if (typeof exposure.exposureId !== 'string' || typeof exposure.packageRelativeTarget !== 'string') {
    fail('consumer-profile exposure identity changed');
  }
}

const compilerOptions = denormalizeCompilerValue(input.compilerOptions, 'compiler options');
compilerOptions.traceResolution = true;
const resolutionMode = input.mode === 'import' ? ts.ModuleKind.ESNext : ts.ModuleKind.CommonJS;
const traces = [];
const host = { ...ts.sys, trace(message) { traces.push(message); } };
const compilerResult = ts.resolveModuleName(
  input.specifier,
  path.join(root, ...input.containingFile.split('/')),
  compilerOptions,
  host,
  undefined,
  undefined,
  resolutionMode,
);
const resolvedCompiler = compilerResult.resolvedModule
  ? repositoryPath(compilerResult.resolvedModule.resolvedFileName, 'compiler resolution')
  : null;
const selectedCompiler = selectedCompilerExposure(traces, input.exposures, resolvedCompiler);
const stableTraces = traces.map(stableTrace);

let runtimePath = null;
let runtimeError = null;
try {
  const resolved = input.mode === 'import'
    ? import.meta.resolve(input.specifier)
    : require.resolve(input.specifier);
  runtimePath = repositoryPath(
    resolved.startsWith('file:') ? fileURLToPath(resolved) : resolved,
    'runtime resolution',
  );
} catch (error) {
  runtimeError = error instanceof Error ? `${error.name}:${error.code || ''}` : 'unknown';
}
const selectedRuntime = runtimePath === null
  ? { exposureId: null, ambiguous: false }
  : selectedRuntimeExposure(runtimePath, input.exposures);

process.stdout.write(`${JSON.stringify({
  schemaVersion: SCHEMA_VERSION,
  typescriptVersion: ts.version,
  nodeVersion: process.versions.node,
  compilerModuleResolution: ts.ModuleResolutionKind[ts.getEmitModuleResolutionKind(compilerOptions)],
  compilerConditions: ts.getConditions(compilerOptions, resolutionMode),
  customConditions: compilerOptions.customConditions || [],
  compiler: {
    selectedExposureId: selectedCompiler.exposureId,
    ambiguous: selectedCompiler.ambiguous,
    resolvedRepositoryPath: resolvedCompiler,
    evidenceSha256: digest({ traces: stableTraces, selectedCompiler, resolvedCompiler }),
  },
  runtime: {
    selectedExposureId: selectedRuntime.exposureId,
    ambiguous: selectedRuntime.ambiguous,
    resolvedRepositoryPath: runtimePath,
    evidenceSha256: digest({ runtimePath, runtimeError, selectedRuntime }),
  },
})}\n`);
