use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::btree_map;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use move_binary_format::file_format::{AbilitySet, SignatureToken, Visibility};
use move_binary_format::CompiledModule;
use move_stackless_bytecode_2::from_compiled_modules;
use sui_sdk::types::base_types::ObjectID;

#[derive(Debug, Copy, Clone, ValueEnum)]
enum MvrNetwork {
    Mainnet,
    Testnet,
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Verify Move bytecode inventory matches RPC normalized modules"
)]
struct Args {
    /// On-chain package id (0x...). Can be provided multiple times.
    #[arg(long, value_name = "ID")]
    package_id: Vec<String>,

    /// Read additional ids from a file (1 id per line; '#' comments allowed).
    #[arg(long, value_name = "PATH")]
    package_ids_file: Option<PathBuf>,

    /// Read ids from an MVR catalog.json (uses *package_info_id fields).
    #[arg(long, value_name = "PATH")]
    mvr_catalog: Option<PathBuf>,

    /// Which MVR catalog id field to use.
    #[arg(long, value_enum, default_value_t = MvrNetwork::Mainnet)]
    mvr_network: MvrNetwork,

    /// RPC URL (default: mainnet fullnode)
    #[arg(long, default_value = "https://fullnode.mainnet.sui.io:443")]
    rpc_url: String,

    /// Write a batch summary as JSONL.
    #[arg(long, value_name = "PATH")]
    summary_jsonl: Option<PathBuf>,

    /// Limit the number of packages processed.
    #[arg(long, value_name = "N")]
    max_packages: Option<usize>,

    /// Print module names (single-package mode)
    #[arg(long, default_value_t = false)]
    list_modules: bool,

    /// Batch-run local bytecode extraction over entries in `sui-packages/packages/mainnet_most_used`.
    #[arg(long, default_value_t = false)]
    batch_local_bytecode_mainnet_most_used: bool,

    /// Build index artifacts from a summary JSONL (writes into --index-out-dir)
    #[arg(long)]
    index_from_summary_jsonl: Option<PathBuf>,

    /// Output directory for `--index-from-summary-jsonl`
    #[arg(long, default_value = "/tmp/bytecode_move_model2_index")]
    index_out_dir: PathBuf,

    /// Verify RPC normalized module inventory matches local compiled module inventory.
    #[arg(long, value_name = "PATH")]
    verify_inventory_from_summary_jsonl: Option<PathBuf>,

    /// Output JSONL path for inventory verification.
    #[arg(long, value_name = "PATH")]
    verify_inventory_out_jsonl: Option<PathBuf>,

    /// Sample size for inventory verification (defaults to all rows).
    #[arg(long, value_name = "N")]
    verify_inventory_sample_size: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LocalBytecodeModuleList {
    package_id: String,
    dataset: String,
    resolved_artifact_dir: String,
    resolved_bytecode_modules_dir: String,
    module_names: Vec<String>,
    stackless_summary: Option<StacklessSummary>,
    stackless_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct StacklessSummary {
    packages: usize,
    modules: usize,
    functions: usize,
    structs: usize,
    not_implemented_instructions: usize,
    stack_underflow_pops: usize,
}

fn count_stackless(
    bytecode: &move_stackless_bytecode_2::ast::StacklessBytecode,
) -> StacklessSummary {
    let mut packages = 0usize;
    let mut modules = 0usize;
    let mut functions = 0usize;
    let structs = 0usize;

    for pkg in &bytecode.packages {
        packages += 1;
        for (_mname, m) in &pkg.modules {
            modules += 1;
            functions += m.functions.len();
        }
    }

    StacklessSummary {
        packages,
        modules,
        functions,
        structs,
        not_implemented_instructions: 0,
        stack_underflow_pops: 0,
    }
}

fn count_stackless_with_stats(
    bytecode: &move_stackless_bytecode_2::ast::StacklessBytecode,
    stats: move_stackless_bytecode_2::translate::TranslationStats,
) -> StacklessSummary {
    let mut s = count_stackless(bytecode);
    s.not_implemented_instructions = stats.not_implemented_instructions;
    s.stack_underflow_pops = stats.stack_underflow_pops;
    s
}

fn load_compiled_modules_from_bytecode_modules_dir(
    bytecode_modules_dir: &Path,
) -> Result<Vec<CompiledModule>> {
    let mut modules = Vec::new();
    for entry in fs::read_dir(bytecode_modules_dir)
        .with_context(|| format!("read_dir {}", bytecode_modules_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("mv") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let module = CompiledModule::deserialize_with_defaults(&bytes)
            .with_context(|| format!("deserialize {}", path.display()))?;
        modules.push(module);
    }
    Ok(modules)
}

fn parse_linkage_deps_from_artifact_dir(artifact_dir: &Path) -> Result<Vec<String>> {
    let bcs_path = artifact_dir.join("bcs.json");
    let bcs_text =
        fs::read_to_string(&bcs_path).with_context(|| format!("read {}", bcs_path.display()))?;
    let bcs_value: Value = serde_json::from_str(&bcs_text)
        .with_context(|| format!("parse json {}", bcs_path.display()))?;

    let mut deps = Vec::new();
    if let Some(linkage) = bcs_value.get("linkageTable").and_then(Value::as_object) {
        for (dep_id, _info) in linkage {
            deps.push(dep_id.to_string());
        }
    }
    Ok(deps)
}

fn try_load_local_modules_for_package(package_id: &str) -> Result<Option<Vec<CompiledModule>>> {
    let artifact_dir = match sui_packages_artifact_dir_for_package_id(package_id)
        .and_then(|p| p.canonicalize().map_err(|e| anyhow!(e)))
    {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let bytecode_dir = artifact_dir.join("bytecode_modules");
    let mods = load_compiled_modules_from_bytecode_modules_dir(&bytecode_dir)
        .with_context(|| format!("load local modules {}", package_id))?;
    Ok(Some(mods))
}

async fn fetch_compiled_modules_via_rpc(
    client: Arc<sui_sdk::SuiClient>,
    package_id: ObjectID,
) -> Result<Vec<CompiledModule>> {
    // Fetch raw package object and extract module bytes.
    let resp = client
        .read_api()
        .get_object_with_options(
            package_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::new().with_bcs(),
        )
        .await
        .with_context(|| format!("fetch package object {}", package_id))?;

    let data = resp
        .data
        .ok_or_else(|| anyhow!("missing object data for {}", package_id))?;
    let bcs = data
        .bcs
        .ok_or_else(|| anyhow!("missing bcs for {}", package_id))?;

    let pkg = match bcs {
        sui_sdk::rpc_types::SuiRawData::Package(pkg) => pkg,
        _ => return Err(anyhow!("object {} is not a package", package_id)),
    };

    let mut modules = Vec::new();
    for (name, bytes) in pkg.module_map {
        let module = CompiledModule::deserialize_with_defaults(&bytes)
            .with_context(|| format!("deserialize rpc module {}::{}", package_id, name))?;
        modules.push(module);
    }
    Ok(modules)
}

async fn fetch_dependency_package_ids_via_rpc(
    client: Arc<sui_sdk::SuiClient>,
    package_id: ObjectID,
) -> Result<Vec<String>> {
    let resp = client
        .read_api()
        .get_object_with_options(
            package_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::new().with_bcs(),
        )
        .await
        .with_context(|| format!("fetch package object {}", package_id))?;

    let data = resp
        .data
        .ok_or_else(|| anyhow!("missing object data for {}", package_id))?;
    let bcs = data
        .bcs
        .ok_or_else(|| anyhow!("missing bcs for {}", package_id))?;

    let pkg = match bcs {
        sui_sdk::rpc_types::SuiRawData::Package(pkg) => pkg,
        _ => return Err(anyhow!("object {} is not a package", package_id)),
    };

    let deps = pkg
        .linkage_table
        .into_iter()
        .map(|(id, _linkage)| id.to_string())
        .collect::<Vec<_>>();
    Ok(deps)
}

async fn load_compiled_modules_with_rpc_deps(
    client: Arc<sui_sdk::SuiClient>,
    root_package_id: &str,
) -> Result<Vec<CompiledModule>> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = vec![root_package_id.to_string()];
    let mut all_modules: Vec<CompiledModule> = Vec::new();

    // Ensure we always load the root package modules, even if local dataset lookup fails.
    // This prevents later inventory verification from operating on deps-only results.
    if let Some(mut root_local) = try_load_local_modules_for_package(root_package_id)? {
        all_modules.append(&mut root_local);
    } else {
        let root_oid = object_id_from_hex_str(root_package_id)
            .map_err(|e| anyhow!("invalid root package id {}: {}", root_package_id, e))?;
        let mut root_rpc = fetch_compiled_modules_via_rpc(Arc::clone(&client), root_oid).await?;
        all_modules.append(&mut root_rpc);
    }

    while let Some(pid) = queue.pop() {
        if !seen.insert(pid.clone()) {
            continue;
        }

        // Root already loaded above.
        if pid == root_package_id {
            continue;
        }

        if let Some(mut local_mods) = try_load_local_modules_for_package(&pid)? {
            all_modules.append(&mut local_mods);

            // Only local artifacts have bcs.json linkage info.
            let artifact_dir = sui_packages_artifact_dir_for_package_id(&pid)?
                .canonicalize()
                .with_context(|| format!("canonicalize artifact dir for {}", pid))?;
            for dep in parse_linkage_deps_from_artifact_dir(&artifact_dir)? {
                if !seen.contains(&dep) {
                    queue.push(dep);
                }
            }
            continue;
        }

        // Not in local dataset; fetch from RPC.
        // Dependency IDs may be 0x-prefixed 64-hex; ObjectID::from_str expects the same.
        let oid = object_id_from_hex_str(&pid)
            .map_err(|e| anyhow!("invalid dep package id {}: {}", pid, e))?;

        // Discover additional deps from the on-chain linkage table.
        if let Ok(deps) = fetch_dependency_package_ids_via_rpc(Arc::clone(&client), oid).await {
            for dep in deps {
                if !seen.contains(&dep) {
                    queue.push(dep);
                }
            }
        }

        let mut rpc_mods = fetch_compiled_modules_via_rpc(Arc::clone(&client), oid).await?;
        all_modules.append(&mut rpc_mods);
    }

    Ok(all_modules)
}

fn extract_module_names_from_bytecode_modules_dir(
    bytecode_modules_dir: &Path,
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(bytecode_modules_dir)
        .with_context(|| format!("read_dir {}", bytecode_modules_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("mv") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let module = CompiledModule::deserialize_with_defaults(&bytes)
            .with_context(|| format!("deserialize {}", path.display()))?;
        names.push(module.self_id().name().to_string());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn canonicalize_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old_map = std::mem::take(map);
            let mut entries: Vec<(String, Value)> = old_map.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            for (_, v) in entries.iter_mut() {
                canonicalize_json_value(v);
            }

            for (k, v) in entries {
                map.insert(k, v);
            }
        }
        Value::Array(values) => {
            for v in values.iter_mut() {
                canonicalize_json_value(v);
            }
        }
        _ => {}
    }
}

fn collect_package_ids(args: &Args) -> Result<Vec<String>> {
    let mut ids = BTreeSet::<String>::new();

    for id in &args.package_id {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            ids.insert(trimmed.to_string());
        }
    }

    if let Some(path) = args.package_ids_file.as_ref() {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            ids.insert(line.to_string());
        }
    }

    if let Some(path) = args.mvr_catalog.as_ref() {
        let catalog_text =
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let catalog: Value = serde_json::from_str(&catalog_text)
            .with_context(|| format!("parse {}", path.display()))?;
        let Some(names) = catalog.get("names").and_then(Value::as_array) else {
            return Err(anyhow!("mvr catalog missing 'names' array"));
        };

        let field = match args.mvr_network {
            MvrNetwork::Mainnet => "mainnet_package_info_id",
            MvrNetwork::Testnet => "testnet_package_info_id",
        };

        for item in names {
            if let Some(id) = item.get(field).and_then(Value::as_str) {
                let trimmed = id.trim();
                if !trimmed.is_empty() {
                    ids.insert(trimmed.to_string());
                }
            }
        }
    }

    let mut ids: Vec<String> = ids.into_iter().collect();
    if let Some(max) = args.max_packages {
        ids.truncate(max);
    }
    Ok(ids)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct TypeSig(String);

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionInv {
    visibility: Option<String>,
    is_entry: Option<bool>,
    type_params: Option<usize>,
    params: Vec<TypeSig>,
    returns: Vec<TypeSig>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct StructInv {
    abilities: Vec<String>,
    type_params: Option<usize>,
    fields: Vec<(String, TypeSig)>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ModuleInventory {
    functions: BTreeMap<String, FunctionInv>,
    structs: BTreeMap<String, StructInv>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageInventory {
    modules: BTreeMap<String, ModuleInventory>,
}

#[derive(Debug, serde::Serialize)]
struct InventoryVerifyRow {
    resolved_package_id: String,
    ok: bool,
    error: Option<String>,
    modules_missing_local: Vec<String>,
    modules_missing_rpc: Vec<String>,
    modules_with_diffs: Vec<String>,
    diff_summary: BTreeMap<String, usize>,
}

fn stable_json(v: &Value) -> String {
    let mut v = v.clone();
    canonicalize_json_value(&mut v);
    serde_json::to_string(&v).expect("serialize")
}

fn type_sig_from_value(v: &Value) -> TypeSig {
    TypeSig(stable_json(v))
}

fn stable_debug<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}")
}

/// Convert SignatureToken to RPC-compatible JSON format.
/// RPC uses PascalCase primitive types, camelCase keys, and short 0x addresses.
fn type_sig_from_token(module: &CompiledModule, token: &SignatureToken) -> TypeSig {
    fn to_rpc_json(module: &CompiledModule, token: &SignatureToken) -> Value {
        match token {
            SignatureToken::Bool => Value::String("Bool".to_string()),
            SignatureToken::U8 => Value::String("U8".to_string()),
            SignatureToken::U16 => Value::String("U16".to_string()),
            SignatureToken::U32 => Value::String("U32".to_string()),
            SignatureToken::U64 => Value::String("U64".to_string()),
            SignatureToken::U128 => Value::String("U128".to_string()),
            SignatureToken::U256 => Value::String("U256".to_string()),
            SignatureToken::Address => Value::String("Address".to_string()),
            SignatureToken::Signer => Value::String("Signer".to_string()),
            SignatureToken::Vector(inner) => {
                json!({"Vector": to_rpc_json(module, inner)})
            }
            SignatureToken::Datatype(idx) => {
                let handle = module.datatype_handle_at(*idx);
                let mod_handle = module.module_handle_at(handle.module);
                let addr = module
                    .address_identifier_at(mod_handle.address)
                    .to_hex_literal();
                let mod_name = module.identifier_at(mod_handle.name).as_str();
                let name = module.identifier_at(handle.name).as_str();
                json!({
                    "Struct": {
                        "address": addr,
                        "module": mod_name,
                        "name": name,
                        "typeArguments": []
                    }
                })
            }
            SignatureToken::DatatypeInstantiation(inst) => {
                let (idx, type_args) = inst.as_ref();
                let handle = module.datatype_handle_at(*idx);
                let mod_handle = module.module_handle_at(handle.module);
                let addr = module
                    .address_identifier_at(mod_handle.address)
                    .to_hex_literal();
                let mod_name = module.identifier_at(mod_handle.name).as_str();
                let name = module.identifier_at(handle.name).as_str();
                let args: Vec<Value> = type_args.iter().map(|t| to_rpc_json(module, t)).collect();
                json!({
                    "Struct": {
                        "address": addr,
                        "module": mod_name,
                        "name": name,
                        "typeArguments": args
                    }
                })
            }
            SignatureToken::Reference(inner) => {
                json!({"Reference": to_rpc_json(module, inner)})
            }
            SignatureToken::MutableReference(inner) => {
                json!({"MutableReference": to_rpc_json(module, inner)})
            }
            SignatureToken::TypeParameter(idx) => {
                json!({"TypeParameter": *idx})
            }
        }
    }
    TypeSig(stable_json(&to_rpc_json(module, token)))
}

fn abilities_to_vec(abilities: &AbilitySet) -> Vec<String> {
    let mut out = Vec::new();
    if abilities.has_copy() {
        out.push("copy".to_string());
    }
    if abilities.has_drop() {
        out.push("drop".to_string());
    }
    if abilities.has_key() {
        out.push("key".to_string());
    }
    if abilities.has_store() {
        out.push("store".to_string());
    }
    out.sort();
    out
}

fn visibility_to_string(v: Visibility) -> String {
    stable_debug(&v)
}

fn module_inventory_from_compiled_module(m: &CompiledModule) -> ModuleInventory {
    let mut functions = BTreeMap::new();
    let mut structs = BTreeMap::new();

    for def in m.function_defs() {
        // RPC normalized modules include:
        // - Public functions
        // - Friend functions
        // - Entry functions (even if private visibility)
        // Skip non-entry private functions
        if matches!(def.visibility, Visibility::Private) && !def.is_entry {
            continue;
        }

        let handle = m.function_handle_at(def.function);
        let name = m.identifier_at(handle.name).as_str().to_string();

        let visibility = Some(visibility_to_string(def.visibility));
        let is_entry = Some(def.is_entry);
        let type_params = Some(handle.type_parameters.len());

        let params_sig = m.signature_at(handle.parameters);
        let params = params_sig
            .0
            .iter()
            .map(|t| type_sig_from_token(m, t))
            .collect::<Vec<_>>();

        let returns_sig = m.signature_at(handle.return_);
        let returns = returns_sig
            .0
            .iter()
            .map(|t| type_sig_from_token(m, t))
            .collect::<Vec<_>>();

        functions.insert(
            name,
            FunctionInv {
                visibility,
                is_entry,
                type_params,
                params,
                returns,
            },
        );
    }

    for def in m.struct_defs() {
        let handle = m.datatype_handle_at(def.struct_handle);
        let name = m.identifier_at(handle.name).as_str().to_string();
        let abilities = abilities_to_vec(&handle.abilities);
        let type_params = Some(handle.type_parameters.len());

        let mut fields: Vec<(String, TypeSig)> = Vec::new();
        if let Some(field_info) = def.fields() {
            for f in field_info {
                let fname = m.identifier_at(f.name).as_str().to_string();
                let fty = type_sig_from_token(m, &f.signature.0);
                fields.push((fname, fty));
            }
        }
        fields.sort();

        structs.insert(
            name,
            StructInv {
                abilities,
                type_params,
                fields,
            },
        );
    }

    ModuleInventory { functions, structs }
}

fn package_inventory_from_compiled_modules(modules: &[CompiledModule]) -> PackageInventory {
    let mut out = BTreeMap::new();
    for m in modules {
        let name = m.self_id().name().as_str().to_string();
        out.insert(name, module_inventory_from_compiled_module(m));
    }
    PackageInventory { modules: out }
}
fn module_inventory_from_normalized_value(module: &Value) -> Result<ModuleInventory> {
    let mut functions = BTreeMap::new();
    let mut structs = BTreeMap::new();

    // RPC uses "exposedFunctions" key, not "functions"
    if let Some(funcs) = module.get("exposedFunctions").and_then(Value::as_object) {
        for (fname, fval) in funcs {
            let visibility = fval
                .get("visibility")
                .and_then(Value::as_str)
                .map(|s| s.to_string());

            // RPC uses camelCase: isEntry, typeParameters
            let is_entry = fval.get("isEntry").and_then(Value::as_bool);

            let type_params = fval
                .get("typeParameters")
                .and_then(Value::as_array)
                .map(|a| a.len());

            let params = fval
                .get("parameters")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(type_sig_from_value).collect())
                .unwrap_or_default();

            let returns = fval
                .get("return")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(type_sig_from_value).collect())
                .unwrap_or_default();

            functions.insert(
                fname.clone(),
                FunctionInv {
                    visibility,
                    is_entry,
                    type_params,
                    params,
                    returns,
                },
            );
        }
    }

    if let Some(sobjs) = module.get("structs").and_then(Value::as_object) {
        for (sname, sval) in sobjs {
            // RPC uses nested "abilities.abilities" with PascalCase values
            let mut abilities = sval
                .get("abilities")
                .and_then(|v| v.get("abilities"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.to_lowercase()) // Normalize to lowercase
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            abilities.sort();

            // RPC uses camelCase: typeParameters
            let type_params = sval
                .get("typeParameters")
                .and_then(Value::as_array)
                .map(|a| a.len());

            let mut fields: Vec<(String, TypeSig)> = Vec::new();
            if let Some(farr) = sval.get("fields").and_then(Value::as_array) {
                for f in farr {
                    let fname = f
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("<unknown>")
                        .to_string();
                    let fty = f
                        .get("type")
                        .map(type_sig_from_value)
                        .unwrap_or(TypeSig("null".to_string()));
                    fields.push((fname, fty));
                }
            }
            fields.sort();

            structs.insert(
                sname.clone(),
                StructInv {
                    abilities,
                    type_params,
                    fields,
                },
            );
        }
    }

    Ok(ModuleInventory { functions, structs })
}

fn package_inventory_from_normalized_modules(modules_value: &Value) -> Result<PackageInventory> {
    let mut modules = BTreeMap::new();
    let Some(mobj) = modules_value.as_object() else {
        return Err(anyhow!("expected modules to be an object"));
    };

    for (mname, mval) in mobj {
        // RPC keys are module names; to compare with local bytecode, key by module self-name.
        let name = mval
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(mname)
            .to_string();
        modules.insert(name, module_inventory_from_normalized_value(mval)?);
    }

    Ok(PackageInventory { modules })
}

fn diff_module_inventory(
    a: &ModuleInventory,
    b: &ModuleInventory,
) -> (bool, BTreeMap<String, usize>) {
    let mut diffs: BTreeMap<String, usize> = BTreeMap::new();

    for (k, va) in &a.functions {
        match b.functions.get(k) {
            None => {
                *diffs
                    .entry("function_missing_other".to_string())
                    .or_default() += 1
            }
            Some(vb) => {
                if va != vb {
                    *diffs.entry("function_mismatch".to_string()).or_default() += 1;
                }
            }
        }
    }
    for k in b.functions.keys() {
        if !a.functions.contains_key(k) {
            *diffs
                .entry("function_missing_self".to_string())
                .or_default() += 1;
        }
    }

    for (k, va) in &a.structs {
        match b.structs.get(k) {
            None => *diffs.entry("struct_missing_other".to_string()).or_default() += 1,
            Some(vb) => {
                if va != vb {
                    *diffs.entry("struct_mismatch".to_string()).or_default() += 1;
                }
            }
        }
    }
    for k in b.structs.keys() {
        if !a.structs.contains_key(k) {
            *diffs.entry("struct_missing_self".to_string()).or_default() += 1;
        }
    }

    (diffs.is_empty(), diffs)
}
#[derive(Debug, Serialize, serde::Deserialize)]
struct IndexMeta {
    source_jsonl: String,
    rows: usize,
    ok: usize,
    error: usize,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct IndexArtifacts {
    meta: IndexMeta,
    by_package_id: BTreeMap<String, u64>,
    errors: BTreeMap<String, u64>,
}

fn build_index_from_summary_jsonl(
    summary_jsonl_path: &std::path::Path,
) -> anyhow::Result<IndexArtifacts> {
    let file = std::fs::File::open(summary_jsonl_path).with_context(|| {
        format!(
            "failed to open summary jsonl: {}",
            summary_jsonl_path.display()
        )
    })?;
    let reader = std::io::BufReader::new(file);

    let mut rows = 0usize;
    let mut ok = 0usize;
    let mut by_package_id: BTreeMap<String, u64> = BTreeMap::new();
    let mut errors: BTreeMap<String, u64> = BTreeMap::new();

    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        rows += 1;
        let v: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("failed to parse jsonl line {}", rows))?;
        let package_id = v
            .get("resolved_package_id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("package_id").and_then(|x| x.as_str()))
            .unwrap_or("<missing>")
            .to_string();

        match by_package_id.entry(package_id) {
            btree_map::Entry::Vacant(e) => {
                e.insert(rows as u64);
            }
            btree_map::Entry::Occupied(_) => {}
        }

        let err = v.get("stackless_error").and_then(|x| x.as_str());
        if let Some(err) = err {
            *errors.entry(err.to_string()).or_insert(0) += 1;
        } else {
            ok += 1;
        }
    }

    Ok(IndexArtifacts {
        meta: IndexMeta {
            source_jsonl: summary_jsonl_path.display().to_string(),
            rows,
            ok,
            error: rows.saturating_sub(ok),
        },
        by_package_id,
        errors,
    })
}

fn write_index_artifacts(index: &IndexArtifacts, out_dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create out dir: {}", out_dir.display()))?;

    let meta_path = out_dir.join("meta.json");
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&index.meta)?)
        .with_context(|| format!("failed to write {}", meta_path.display()))?;

    let by_pkg_path = out_dir.join("by_package_id.json");
    std::fs::write(
        &by_pkg_path,
        serde_json::to_vec_pretty(&index.by_package_id)?,
    )
    .with_context(|| format!("failed to write {}", by_pkg_path.display()))?;

    let errors_path = out_dir.join("errors.json");
    std::fs::write(&errors_path, serde_json::to_vec_pretty(&index.errors)?)
        .with_context(|| format!("failed to write {}", errors_path.display()))?;

    Ok(())
}

fn read_package_ids_from_summary_jsonl(
    summary_jsonl_path: &std::path::Path,
) -> anyhow::Result<Vec<String>> {
    let file = std::fs::File::open(summary_jsonl_path).with_context(|| {
        format!(
            "failed to open summary jsonl: {}",
            summary_jsonl_path.display()
        )
    })?;
    let reader = std::io::BufReader::new(file);

    let mut ids = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(id) = v
                .get("resolved_package_id")
                .and_then(|x| x.as_str())
                .or_else(|| v.get("package_id").and_then(|x| x.as_str()))
            {
                ids.push(id.to_string());
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn sui_packages_artifact_dir_for_package_id(package_id: &str) -> Result<PathBuf> {
    let package_id = package_id.strip_prefix("0x").unwrap_or(package_id);
    // Left-pad with zeros to 64 hex chars if needed (handles short addresses like 0x2 or 63-char ids).
    let package_id = format!("{:0>64}", package_id);
    if package_id.len() != 64 || !package_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "expected 64-hex package id (optionally 0x-prefixed), got: {}",
            package_id
        ));
    }

    let prefix = &package_id[0..2];
    let entry_name = &package_id[2..];

    // Dataset layout is `$SUI_PACKAGES_DIR/packages/mainnet_most_used/0x??/<suffix62>`
    // Default: ../sui-packages (relative to cwd)
    let sui_packages_dir =
        std::env::var("SUI_PACKAGES_DIR").unwrap_or_else(|_| "../sui-packages".to_string());
    Ok(PathBuf::from(format!(
        "{}/packages/mainnet_most_used/0x{}/{}",
        sui_packages_dir, prefix, entry_name
    )))
}

/// Read the originalPackageId from metadata.json if present. Falls back to the passed id.
fn read_original_package_id_from_metadata(package_id: &str) -> Result<String> {
    let artifact_dir = sui_packages_artifact_dir_for_package_id(package_id)?
        .canonicalize()
        .ok();
    let artifact_dir = match artifact_dir {
        Some(d) => d,
        None => return Ok(package_id.to_string()),
    };
    let meta_path = artifact_dir.join("metadata.json");
    if !meta_path.exists() {
        return Ok(package_id.to_string());
    }
    let data = fs::read_to_string(&meta_path)?;
    let v: serde_json::Value = serde_json::from_str(&data)?;
    if let Some(orig) = v.get("originalPackageId").and_then(|v| v.as_str()) {
        return Ok(orig.to_string());
    }
    Ok(package_id.to_string())
}

fn iter_mainnet_most_used_package_ids(limit: usize) -> Result<Vec<String>> {
    let sui_packages_dir =
        std::env::var("SUI_PACKAGES_DIR").unwrap_or_else(|_| "../sui-packages".to_string());
    let dataset_root = PathBuf::from(format!("{}/packages/mainnet_most_used", sui_packages_dir));

    let mut entries: Vec<(String, String)> = Vec::new();
    for prefix_dir in fs::read_dir(&dataset_root)
        .with_context(|| format!("read_dir {}", dataset_root.display()))?
    {
        let prefix_dir = prefix_dir?;
        let prefix_path = prefix_dir.path();
        if !prefix_path.is_dir() {
            continue;
        }
        let prefix_name = prefix_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if !prefix_name.starts_with("0x") {
            continue;
        }
        for pkg_dir in fs::read_dir(&prefix_path)? {
            let pkg_dir = pkg_dir?;
            let pkg_path = pkg_dir.path();
            let pkg_name = pkg_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            if pkg_name.is_empty() {
                continue;
            }
            entries.push((prefix_name.clone(), pkg_name));
        }
    }

    entries.sort();

    let mut out = Vec::new();
    for (prefix, suffix62) in entries.into_iter().take(limit) {
        let prefix_hex = prefix.strip_prefix("0x").unwrap_or(prefix.as_str());
        out.push(format!("0x{prefix_hex}{suffix62}"));
    }
    Ok(out)
}

fn object_id_from_hex_str(id: &str) -> anyhow::Result<ObjectID> {
    ObjectID::from_str(id).with_context(|| format!("invalid object id: {id}"))
}

async fn run_single_local_sui_packages_with_rpc_deps(
    client: Arc<sui_sdk::SuiClient>,
    package_id: &str,
) -> Result<LocalBytecodeModuleList> {
    let artifact_dir = sui_packages_artifact_dir_for_package_id(package_id)?;
    let resolved = artifact_dir
        .canonicalize()
        .with_context(|| format!("canonicalize {}", artifact_dir.display()))?;

    let bytecode_modules_dir = resolved.join("bytecode_modules");
    let module_names = extract_module_names_from_bytecode_modules_dir(&bytecode_modules_dir)?;

    let compiled_modules =
        load_compiled_modules_with_rpc_deps(Arc::clone(&client), package_id).await?;
    let mut stackless_error: Option<String> = None;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let stackless_summary = match std::panic::catch_unwind(|| {
        from_compiled_modules(compiled_modules, /* optimize */ true)
    }) {
        Ok(Ok((_model, stackless, stats))) => Some(count_stackless_with_stats(&stackless, stats)),
        Ok(Err(e)) => {
            stackless_error = Some(format!("error: {e:#}"));
            None
        }
        Err(panic_payload) => {
            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic>".to_string()
            };
            stackless_error = Some(format!("panic: {msg}"));
            None
        }
    };
    std::panic::set_hook(prev_hook);

    Ok(LocalBytecodeModuleList {
        package_id: package_id.to_string(),
        dataset: "sui-packages/mainnet_most_used".to_string(),
        resolved_artifact_dir: resolved.display().to_string(),
        resolved_bytecode_modules_dir: bytecode_modules_dir.display().to_string(),
        module_names,
        stackless_summary,
        stackless_error,
    })
}

async fn verify_one_package_inventory(
    client: Arc<sui_sdk::SuiClient>,
    package_id_str: &str,
) -> InventoryVerifyRow {
    let mut row = InventoryVerifyRow {
        resolved_package_id: package_id_str.to_string(),
        ok: false,
        error: None,
        modules_missing_local: vec![],
        modules_missing_rpc: vec![],
        modules_with_diffs: vec![],
        diff_summary: BTreeMap::new(),
    };

    let rpc_oid = match object_id_from_hex_str(package_id_str) {
        Ok(v) => v,
        Err(e) => {
            row.error = Some(format!("invalid_object_id: {e:#}"));
            return row;
        }
    };

    let rpc_modules = match client
        .read_api()
        .get_normalized_move_modules_by_package(rpc_oid)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            row.error = Some(format!("rpc_normalized_modules_error: {e:#}"));
            return row;
        }
    };
    let mut rpc_modules_value = match serde_json::to_value(&rpc_modules) {
        Ok(v) => v,
        Err(e) => {
            row.error = Some(format!("rpc_normalized_modules_serialize_error: {e:#}"));
            return row;
        }
    };
    canonicalize_json_value(&mut rpc_modules_value);

    let rpc_inv = match package_inventory_from_normalized_modules(&rpc_modules_value) {
        Ok(v) => v,
        Err(e) => {
            row.error = Some(format!("rpc_inventory_parse_error: {e:#}"));
            return row;
        }
    };

    let local_compiled =
        match load_compiled_modules_with_rpc_deps(Arc::clone(&client), package_id_str).await {
            Ok(v) => v,
            Err(e) => {
                row.error = Some(format!("local_compiled_modules_error: {e:#}"));
                return row;
            }
        };

    let addrs_before: std::collections::BTreeSet<String> = local_compiled
        .iter()
        .map(|m| m.self_id().address().to_hex_literal())
        .collect();

    // For upgraded packages, module bytecode still embeds the original package address.
    let original_id = read_original_package_id_from_metadata(package_id_str)
        .unwrap_or_else(|_| package_id_str.to_string());
    let package_addr = {
        let hex = original_id.strip_prefix("0x").unwrap_or(&original_id);
        let padded = format!("{:0>64}", hex);
        move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", padded))
            .unwrap_or_else(|_| move_core_types::account_address::AccountAddress::from(rpc_oid))
    };
    let local_compiled: Vec<CompiledModule> = local_compiled
        .into_iter()
        .filter(|m| *m.self_id().address() == package_addr)
        .collect();

    if local_compiled.is_empty() {
        row.error = Some(format!(
            "local_package_modules_not_found: package_addr={}, addrs_before={:?}",
            package_addr.to_hex_literal(),
            addrs_before
        ));
        return row;
    }

    let local_inv = package_inventory_from_compiled_modules(&local_compiled);

    for m in rpc_inv.modules.keys() {
        if !local_inv.modules.contains_key(m) {
            row.modules_missing_local.push(m.clone());
        }
    }
    for m in local_inv.modules.keys() {
        if !rpc_inv.modules.contains_key(m) {
            row.modules_missing_rpc.push(m.clone());
        }
    }

    for (mname, rpc_m) in &rpc_inv.modules {
        let Some(local_m) = local_inv.modules.get(mname) else {
            continue;
        };
        let (ok, diffs) = diff_module_inventory(local_m, rpc_m);
        if !ok {
            row.modules_with_diffs.push(mname.clone());
            for (k, v) in diffs {
                *row.diff_summary.entry(k).or_default() += v;
            }
        }
    }

    row.ok = row.error.is_none()
        && row.modules_missing_local.is_empty()
        && row.modules_missing_rpc.is_empty()
        && row.modules_with_diffs.is_empty();
    row
}

async fn run_verify_inventory(
    args: &Args,
    client: Arc<sui_sdk::SuiClient>,
    summary_jsonl_path: &std::path::Path,
) -> Result<PathBuf> {
    let ids = read_package_ids_from_summary_jsonl(summary_jsonl_path)?;
    if ids.is_empty() {
        return Err(anyhow!(
            "no package ids found in summary jsonl: {}",
            summary_jsonl_path.display()
        ));
    }

    let sample_size = args
        .verify_inventory_sample_size
        .unwrap_or(ids.len())
        .min(ids.len());
    let selected = &ids[..sample_size];

    let out_path = args
        .verify_inventory_out_jsonl
        .clone()
        .unwrap_or_else(|| PathBuf::from("/tmp/bytecode_move_model2_verify_inventory.jsonl"));

    let out_file = std::fs::File::create(&out_path).with_context(|| {
        format!(
            "failed to create inventory verify jsonl: {}",
            out_path.display()
        )
    })?;
    let mut out = std::io::BufWriter::new(out_file);

    for package_id in selected {
        let row = verify_one_package_inventory(Arc::clone(&client), package_id).await;
        serde_json::to_writer(&mut out, &row)?;
        out.write_all(b"\n")?;
    }

    out.flush()?;
    Ok(out_path)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let client = Arc::new(
        sui_sdk::SuiClientBuilder::default()
            .build(&args.rpc_url)
            .await
            .context("build sui client")?,
    );

    // Handle verify-inventory mode
    if let Some(ref summary_path) = args.verify_inventory_from_summary_jsonl {
        let out_path = run_verify_inventory(&args, Arc::clone(&client), summary_path).await?;
        println!("inventory verified -> {}", out_path.display());
        return Ok(());
    }

    // Handle index-from-summary-jsonl mode
    if let Some(ref summary_path) = args.index_from_summary_jsonl {
        let index = build_index_from_summary_jsonl(summary_path)?;
        write_index_artifacts(&index, &args.index_out_dir)?;
        println!("index artifacts -> {}", args.index_out_dir.display());
        return Ok(());
    }

    // Handle batch local bytecode mode
    if args.batch_local_bytecode_mainnet_most_used {
        let package_ids =
            iter_mainnet_most_used_package_ids(args.max_packages.unwrap_or(usize::MAX))?;
        let summary_path = args
            .summary_jsonl
            .clone()
            .unwrap_or_else(|| PathBuf::from("/tmp/bytecode_research_mainnet_most_used.jsonl"));
        let out_file = std::fs::File::create(&summary_path)?;
        let mut out = std::io::BufWriter::new(out_file);

        for package_id in package_ids {
            let row =
                match run_single_local_sui_packages_with_rpc_deps(Arc::clone(&client), &package_id)
                    .await
                {
                    Ok(v) => serde_json::json!({
                        "resolved_package_id": package_id,
                        "ok": v.stackless_error.is_none(),
                        "module_names": v.module_names,
                        "stackless_error": v.stackless_error,
                    }),
                    Err(e) => serde_json::json!({
                        "resolved_package_id": package_id,
                        "ok": false,
                        "error": format!("{e:#}"),
                    }),
                };
            serde_json::to_writer(&mut out, &row)?;
            out.write_all(b"\n")?;
        }
        out.flush()?;
        println!("batch summary -> {}", summary_path.display());
        return Ok(());
    }

    // Handle single package mode
    let package_ids = collect_package_ids(&args)?;
    if package_ids.is_empty() {
        eprintln!(
            "No package IDs provided. Use --package-id, --package-ids-file, or --mvr-catalog."
        );
        std::process::exit(1);
    }

    // For now, just run single package extraction
    for package_id in &package_ids {
        match run_single_local_sui_packages_with_rpc_deps(Arc::clone(&client), package_id).await {
            Ok(v) => {
                if args.list_modules {
                    println!("Modules for {}: {:?}", package_id, v.module_names);
                }
                if let Some(ref err) = v.stackless_error {
                    eprintln!("Stackless error for {}: {}", package_id, err);
                }
            }
            Err(e) => {
                eprintln!("Error for {}: {:#}", package_id, e);
            }
        }
    }

    Ok(())
}
