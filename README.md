# sui-move-interface-extractor2

Extract and verify Move bytecode interfaces against on-chain RPC normalized modules.

## What it does

This tool compares Move package interfaces extracted from:
1. **Local bytecode** (`.mv` files from `sui-packages` dataset)
2. **RPC normalized modules** (via `sui_getNormalizedMoveModulesByPackage`)

For each package, it verifies that functions, structs, type signatures, abilities, and visibility match between local compilation and on-chain state.

## Results

Tested against 1,000 most-used mainnet packages:

```
total: 1000
local_ok: 1000
rpc_ok: 1000
interface_ok: 1000
problems: 0
```

## Usage

```bash
# Build
cargo build --release

# Corpus output (detailed stats matching extractor1 schema)
cargo run --release -- \
  --verify-inventory-from-summary-jsonl /path/to/packages.jsonl \
  --corpus-out-dir results/corpus_output

# Legacy simple output
cargo run --release -- \
  --verify-inventory-from-summary-jsonl /path/to/packages.jsonl \
  --verify-inventory-out-jsonl /tmp/results.jsonl

# Verify a sample of N packages
cargo run --release -- \
  --verify-inventory-from-summary-jsonl /path/to/packages.jsonl \
  --verify-inventory-sample-size 100 \
  --corpus-out-dir results/sample_100
```

### Input format

The input JSONL should have rows with `resolved_package_id` or `package_id` fields:

```json
{"resolved_package_id": "0x0000...0002"}
{"resolved_package_id": "0x1234...abcd"}
```

### Output formats

#### Corpus output (`--corpus-out-dir`)

Produces detailed results matching extractor1 schema:

```
corpus_output/
├── corpus_report.jsonl   # Per-package detailed results
├── corpus_summary.json   # Aggregate statistics  
├── index.jsonl           # Package ID index
└── problems.jsonl        # Packages with errors
```

**corpus_report.jsonl row:**
```json
{
  "package_id": "0x...",
  "package_dir": "/path/to/package",
  "local": {
    "modules": 61,
    "structs": 119,
    "functions_total": 786,
    "functions_public": 584,
    "functions_friend": 96,
    "functions_private": 106,
    "functions_native": 68,
    "entry_functions": 27,
    "key_structs": 36
  },
  "rpc": {
    "modules": 61,
    "structs": 119,
    "functions": 683,
    "key_structs": 36
  },
  "rpc_vs_local": {
    "left_count": 61,
    "right_count": 61,
    "missing_in_right": [],
    "extra_in_right": []
  },
  "interface_compare": {
    "modules_compared": 61,
    "structs_compared": 119,
    "struct_mismatches": 0,
    "functions_compared": 683,
    "function_mismatches": 0,
    "mismatches_total": 0
  },
  "error": null
}
```

**corpus_summary.json:**
```json
{
  "total": 1000,
  "local_ok": 1000,
  "rpc_enabled": true,
  "rpc_ok": 1000,
  "rpc_module_match": 1000,
  "interface_compare_enabled": true,
  "interface_ok": 1000,
  "interface_mismatch_packages": 0,
  "interface_mismatches_total": 0,
  "problems": 0
}
```

#### Legacy output (`--verify-inventory-out-jsonl`)

Simple per-package JSONL:
```json
{
  "resolved_package_id": "0x...",
  "ok": true,
  "error": null,
  "modules_missing_local": [],
  "modules_missing_rpc": [],
  "modules_with_diffs": [],
  "diff_summary": {}
}
```

## Requirements

### Bytecode dataset

Set `SUI_PACKAGES_DIR` environment variable to point to your `sui-packages` checkout:

```bash
export SUI_PACKAGES_DIR=/path/to/sui-packages
```

Default: `../sui-packages` (relative to cwd)

### Local Sui vendor checkout

This project depends on a local checkout of the Sui repo with a patch applied to fix a bug in `move-stackless-bytecode-2`. Update the paths in `Cargo.toml` to point to your patched checkout.

See [UPSTREAM_ISSUE.md](./UPSTREAM_ISSUE.md) for the bug report and patch details.

## License

Apache-2.0
