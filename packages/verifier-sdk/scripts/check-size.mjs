// Size budget for the SDK's own code (dependencies are external) plus the
// WASM codec wrapper bundle. Fails CI if either gzipped ESM output grows past
// its budget.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { gzipSync } from "node:zlib";

// Budget for the SDK's own JavaScript code.
const BUDGET_BYTES = 8 * 1024;
// Budget for the WASM codec wrapper bundle (JS glue + .wasm artifact).
// Proposed limit: 64 KiB gzipped. The Rust codec is small; this leaves room
// for the wasm-bindgen glue while keeping the browser verifier lightweight.
const WASM_BUDGET_BYTES = 64 * 1024;

function gzippedSize(path) {
  return gzipSync(readFileSync(path)).length;
}

function sumGzipped(dir, predicate) {
  const files = readdirSync(dir).filter(predicate);
  return files.reduce((sum, f) => sum + gzippedSize(new URL(f, dir)), 0);
}

let failed = false;

// 1. SDK's own ESM output.
const esmDir = new URL("../dist/esm/", import.meta.url);
const esmTotal = sumGzipped(esmDir, (f) => f.endsWith(".js"));
console.log(
  `@lafiya/verifier: ${esmTotal} bytes gzipped (budget ${BUDGET_BYTES})`,
);
if (esmTotal > BUDGET_BYTES) {
  console.error("size budget exceeded: @lafiya/verifier ESM");
  failed = true;
}

// 2. WASM codec wrapper bundle (JS glue + .wasm artifact).
const wasmDir = new URL("../dist/wasm/", import.meta.url);
if (existsSync(wasmDir)) {
  const wasmTotal = sumGzipped(
    wasmDir,
    (f) => f.endsWith(".js") || f.endsWith(".wasm"),
  );
  console.log(
    `@lafiya/verifier (wasm codec): ${wasmTotal} bytes gzipped (budget ${WASM_BUDGET_BYTES})`,
  );
  if (wasmTotal > WASM_BUDGET_BYTES) {
    console.error("size budget exceeded: @lafiya/verifier wasm codec");
    failed = true;
  }
} else {
  console.log(
    `@lafiya/verifier (wasm codec): not built, skipping (budget ${WASM_BUDGET_BYTES})`,
  );
}

if (failed) {
  process.exit(1);
}