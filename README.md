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
rows 1000, ok 1000 (100.0%)
```

## Usage

```bash
# Build
cargo build --release

# Verify inventory for packages listed in a JSONL file
cargo run --release -- \
  --verify-inventory-from-summary-jsonl /path/to/packages.jsonl \
  --verify-inventory-out-jsonl /tmp/results.jsonl

# Verify a sample of N packages
cargo run --release -- \
  --verify-inventory-from-summary-jsonl /path/to/packages.jsonl \
  --verify-inventory-sample-size 100 \
  --verify-inventory-out-jsonl /tmp/results.jsonl
```

### Input format

The input JSONL should have rows with `resolved_package_id` or `package_id` fields:

```json
{"resolved_package_id": "0x0000...0002"}
{"resolved_package_id": "0x1234...abcd"}
```

### Output format

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

Expected dataset structure:
```
$SUI_PACKAGES_DIR/packages/mainnet_most_used/
  0x00/
    00000000000000000000000000000000000000000000000000000000000002/
      bytecode_modules/*.mv
      metadata.json
      bcs.json
```

### Local Sui vendor checkout

This project depends on a local checkout of the Sui repo with a patch applied to fix a bug in `move-stackless-bytecode-2`. Update the paths in `Cargo.toml` to point to your patched checkout.

**Required patch:** The `move-stackless-bytecode-2` crate has a bug where bitwise operations (`BitAnd`, `BitOr`, `Xor`) incorrectly return `Bool` type instead of the integer operand type, causing panics on common packages.

See [UPSTREAM_ISSUE.md](./UPSTREAM_ISSUE.md) for the bug report and patch details.

### Setting up the vendor checkout

1. Clone the Sui repo:
   ```bash
   git clone https://github.com/MystenLabs/sui.git vendor/sui
   cd vendor/sui
   ```

2. Apply the patch to `external-crates/move/crates/move-stackless-bytecode-2/src/translate.rs`:
   ```diff
   - IB::BitAnd => binop!(Op::BitAnd, lhs => N::Type::Bool.into()),
   - IB::BitOr  => binop!(Op::BitOr,  lhs => N::Type::Bool.into()),
   - IB::Xor    => binop!(Op::Xor,    lhs => N::Type::Bool.into()),
   + IB::BitAnd => binop!(Op::BitAnd, lhs => lhs.ty.clone()),
   + IB::BitOr  => binop!(Op::BitOr,  lhs => lhs.ty.clone()),
   + IB::Xor    => binop!(Op::Xor,    lhs => lhs.ty.clone()),
   ```

3. Update `Cargo.toml` paths to point to your vendor checkout.

## License

Apache-2.0
