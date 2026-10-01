"use strict";

if (process.argv.length !== 5) {
  throw new Error("TypeScript proof requires compiler, candidate and private type-root paths");
}
const [compilerPath, candidate, typeRoot] = process.argv.slice(2);
const ts = require(compilerPath);
const options = {
  noEmit: true,
  skipLibCheck: true,
  target: ts.ScriptTarget.ES2022,
  jsx: ts.JsxEmit.Preserve,
  typeRoots: [typeRoot],
};
const program = ts.createProgram({ rootNames: [candidate], options });
if (program.getRootFileNames().length !== 1 || !program.getSourceFile(candidate)) {
  throw new Error("TypeScript proof could not load its exact candidate");
}
if (!program.getSourceFile(ts.getDefaultLibFilePath(options))) {
  throw new Error("TypeScript proof could not load the pinned default library");
}
const diagnostics = ts.getPreEmitDiagnostics(program);
process.stdout.write(JSON.stringify({
  schema_version: 1,
  candidate,
  error_count: diagnostics.filter((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error).length,
}));
