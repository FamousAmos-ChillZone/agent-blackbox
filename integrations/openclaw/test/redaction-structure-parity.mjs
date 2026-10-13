/**
 * Cross-runtime STRUCTURE redaction parity — the TypeScript half.
 *
 * Reads a JSON array of JSON values (path in argv[2]; generated at runtime by
 * `tests/plugins/test_blackbox_redaction_parity.py`), runs each through
 * `redact` (secrets assembled across list items, dict values or dict keys are
 * blanked first — KI-377) and prints the outputs as a JSON array, compared
 * byte-for-byte with Python's `audit.redact`.
 *
 *   npx tsx integrations/openclaw/test/redaction-structure-parity.mjs <cases.json>
 */
import { readFileSync } from "node:fs";

import { redact } from "../src/redact.ts";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map((value) => redact(value))));
