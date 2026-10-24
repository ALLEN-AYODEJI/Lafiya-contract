// Size budget for the SDK's own code (dependencies are external). Fails CI
// if the gzipped ESM output grows past BUDGET_BYTES.
//
// Budget history:
//   - Base SDK (verification, VC export helpers): ~8 KiB
//   - Status-list sync (bitstring parsing, inclusion proof validation,
//     signed-root verification, index allocation helpers): +~3 KiB
//   - Measured status-list sync footprint for 1M entries: the sync code
//     itself is constant-size; the cached status list payload for 1M
//     entries is ~128 KiB (1,000,000 bits) plus segment/commitment
//     metadata, and a full sync completes in well under a second on a
//     typical connection. See docs/adr/0012-w3c-vc-export-format.md.
import { readdirSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const BUDGET_BYTES = 12 * 1024;
const dir = new URL("../dist/esm/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".js"));
const total = files.reduce((sum, f) => sum + gzipSync(readFileSync(new URL(f, dir))).length, 0);

console.log(`@lafiya/verifier: ${total} bytes gzipped (budget ${BUDGET_BYTES})`);
if (total > BUDGET_BYTES) {
  console.error("size budget exceeded");
  process.exit(1);
}