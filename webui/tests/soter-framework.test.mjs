import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const source = readFileSync(new URL('../src/cli.ts', import.meta.url), 'utf8')
const ast = ts.createSourceFile('cli.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
const cli = ast.statements.find(node => ts.isClassDeclaration(node) && node.name?.text === 'Cli')
const method = cli.members.find(node => node.name?.getText(ast) === '#parseSoterLocal')
const code = ts.transpileModule(
  `function ${method.getText(ast).replace('#parseSoterLocal', 'parseSoterLocal')}\nparseSoterLocal`,
  { compilerOptions: { target: ts.ScriptTarget.ES2022 } },
).outputText
const parse = vm.runInNewContext(code, {
  parseCanonicalJson: output => JSON.parse(output),
  isRecord: value => value !== null && typeof value === 'object' && !Array.isArray(value),
})
const base = { version: 1, enabled: false, identities: [], apps: {} }

test('legacy or disabled SOTER configuration defaults the experiment off', () => {
  assert.equal(parse(JSON.stringify(base)).framework_biometrics, false)
  assert.equal(parse(JSON.stringify({ ...base, framework_biometrics: false })).framework_biometrics, false)
})

test('only an explicit boolean enables the framework experiment', () => {
  assert.equal(parse(JSON.stringify({ ...base, framework_biometrics: true })).framework_biometrics, true)
  for (const invalid of ['true', 1, null, {}, []]) {
    assert.throws(() => parse(JSON.stringify({ ...base, framework_biometrics: invalid })))
  }
})
