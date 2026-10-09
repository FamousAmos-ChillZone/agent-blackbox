/**
 * Cross-runtime REDACTION parity — the TypeScript half.
 *
 * Reads a JSON array of input strings (path in argv[2]; the Python test
 * generates them at runtime so no secret-shaped literal lives in the repo),
 * runs each through `redactSecretValues`, and prints the outputs as a JSON
 * array. `tests/plugins/test_blackbox_redaction_parity.py` compares them
 * byte-for-byte with `kernel/redaction.redact_secret_values`.
 *
 * Run with (tsx transpiles the imported .ts module on the fly):
 *   npx tsx integrations/openclaw/test/redaction-parity.mjs <cases.json>
 */
import { readFileSync } from "node:fs";

import { redactSecretValues } from "../src/redact.ts";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map((text) => redactSecretValues(text))));
