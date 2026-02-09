#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MATRIX_FILE="$ROOT_DIR/parity/parity_matrix.json"
MODE="quick"

if [[ "${1:-}" == "--full" ]]; then
  MODE="full"
fi

if [[ ! -f "$MATRIX_FILE" ]]; then
  echo "Matrix file not found: $MATRIX_FILE" >&2
  exit 1
fi

export ROOT_DIR MATRIX_FILE MODE

node <<'NODE'
const fs = require('fs');
const { execSync } = require('child_process');

const root = process.env.ROOT_DIR;
const matrixPath = process.env.MATRIX_FILE;
const mode = process.env.MODE || 'quick';

const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
const items = (matrix.items || []).filter((item) => {
  const itemMode = (item.check && item.check.mode) || 'quick';
  if (mode === 'full') return true;
  return itemMode === 'quick';
});

let total = 0;
let observedDone = 0;
let observedPending = 0;
let drift = 0;

const byPriority = { P0: { total: 0, done: 0 }, P1: { total: 0, done: 0 }, P2: { total: 0, done: 0 } };

for (const item of items) {
  total += 1;
  const expected = item.status;
  const cmd = item.check && item.check.command;
  const priority = item.priority || 'P2';

  if (!byPriority[priority]) byPriority[priority] = { total: 0, done: 0 };
  byPriority[priority].total += 1;

  let observed = 'pending';
  try {
    execSync(cmd, {
      cwd: root,
      stdio: 'ignore',
      shell: '/bin/bash',
      env: process.env,
    });
    observed = 'done';
  } catch {
    observed = 'pending';
  }

  if (observed === 'done') {
    observedDone += 1;
    byPriority[priority].done += 1;
  } else {
    observedPending += 1;
  }

  const ok = observed === expected;
  if (!ok) drift += 1;

  const state = ok ? 'OK' : 'DRIFT';
  console.log(`${state} | ${priority} | ${item.id} | expected=${expected} observed=${observed}`);
}

const percent = total === 0 ? 0 : ((observedDone / total) * 100);
console.log('---');
console.log(`Mode: ${mode}`);
console.log(`Items checked: ${total}`);
console.log(`Observed done: ${observedDone}`);
console.log(`Observed pending: ${observedPending}`);
console.log(`Observed parity percent: ${percent.toFixed(2)}%`);
console.log(`Status drift count: ${drift}`);
console.log('Priority summary:');
for (const p of Object.keys(byPriority).sort()) {
  const v = byPriority[p];
  const pPct = v.total === 0 ? 0 : ((v.done / v.total) * 100);
  console.log(`  ${p}: ${v.done}/${v.total} (${pPct.toFixed(2)}%)`);
}

if (drift > 0) {
  process.exitCode = 2;
}
NODE
