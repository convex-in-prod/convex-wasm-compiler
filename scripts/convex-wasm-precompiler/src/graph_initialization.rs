//! Initialization-only execution of verified, dynamically linked Core Wasm graphs.
//! The caller authenticates package contracts before constructing a graph. Linking
//! retains provider order, shared memory/table ownership and deferred self-GOT fixups.
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use wasmtime::{
    Error as WasmtimeError, Extern, ExternType, Global, GlobalType, Instance, Linker, Memory,
    Module, Ref, Store, Val, error, error::Context as _,
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphInitialization {
    pub base_heap_base: u32,
    pub base_table_size: u64,
    pub constructor_order: Vec<String>,
    pub final_memory_cursor: u32,
    pub final_table_cursor: u64,
    pub module_order: Vec<String>,
    pub relocation_order: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphModuleLayout {
    pub memory_align: u32,
    pub memory_base: u32,
    pub memory_size: u32,
    pub table_align: u32,
    pub table_base: u64,
    pub table_size: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphModuleProvider {
    pub consumer: String,
    pub import_index: usize,
    pub imported_module: String,
    pub imported_name: String,
    pub provider: String,
    pub provider_export: Option<String>,
    pub type_sha256: String,
    pub weak: bool,
}

pub struct GraphModule {
    pub module: Arc<Module>,
    pub layout: GraphModuleLayout,
    pub providers: Vec<GraphModuleProvider>,
}

pub struct GraphModules {
    pub initialization: GraphInitialization,
    pub modules: Vec<GraphModule>,
}

#[derive(Clone)]
struct GeneratedGraphGotBinding {
    global: Global,
    provider: String,
    provider_export: Option<String>,
    weak: bool,
}

type GeneratedGraphGotBindings = BTreeMap<(String, String), GeneratedGraphGotBinding>;

#[derive(Clone)]
pub struct GraphInstances {
    pub modules: Vec<Instance>,
}

pub async fn instantiate<T: Send + 'static>(
    linker: &Linker<T>,
    store: &mut Store<T>,
    graph: &GraphModules,
) -> error::Result<GraphInstances> {
    let modules = graph
        .modules
        .iter()
        .map(|record| record.module.as_ref())
        .collect::<Vec<_>>();
    error::ensure!(
        modules.len() >= 2 && modules.len() == graph.initialization.module_order.len(),
        "module graph lost its manifest order"
    );
    let base_imports = modules[0]
        .imports()
        .enumerate()
        .map(|(index, imported)| {
            let provider = &graph.modules[0].providers[index];
            error::ensure!(
                provider.provider == "host"
                    && provider.import_index == index
                    && provider.imported_module == imported.module()
                    && provider.imported_name == imported.name(),
                "base module import differs from its authenticated host provider"
            );
            linker
                .get(&mut *store, imported.module(), imported.name())
                .context("base module host provider is unavailable")
        })
        .collect::<error::Result<Vec<_>>>()?;
    let base = Instance::new_async(&mut *store, modules[0], &base_imports)
        .await
        .context("instantiate authenticated base module")?;
    let memory = base
        .get_memory(&mut *store, "memory")
        .context("base module does not export memory")?;
    let table = base
        .get_table(&mut *store, "__indirect_function_table")
        .context("base module does not export the function table")?;
    let stack_pointer = base
        .get_global(&mut *store, "__stack_pointer")
        .context("base module does not export __stack_pointer")?;
    let heap_base = base
        .get_global(&mut *store, "__heap_base")
        .context("base module does not export __heap_base")?
        .get(&mut *store)
        .i32()
        .context("base __heap_base is not i32")?;
    error::ensure!(
        u32::try_from(heap_base)? == graph.initialization.base_heap_base
            && table.size(&*store) == graph.initialization.base_table_size,
        "base module layout differs from authenticated graph initialization"
    );
    prepare_generated_emscripten_memory_and_table(
        store,
        base,
        memory,
        table,
        &graph.initialization,
    )
    .await?;

    let mut got = GeneratedGraphGotBindings::new();
    let mut instances = vec![base];
    for (module_index, &module) in modules.iter().enumerate().skip(1) {
        let imports = resolve_generated_emscripten_side_imports(
            store,
            graph,
            module_index,
            module,
            &instances,
            memory,
            table,
            stack_pointer,
            &mut got,
        )?;
        let instance = Instance::new_async(&mut *store, module, &imports)
            .await
            .with_context(|| {
                format!(
                    "instantiate authenticated {} module",
                    graph.initialization.module_order[module_index]
                )
            })?;
        instances.push(instance);
        update_generated_emscripten_self_got(
            store,
            graph,
            module_index,
            table,
            &mut got,
            &instances,
        )?;
    }
    reject_unresolved_generated_emscripten_got(store, graph, &got)?;
    Ok(GraphInstances { modules: instances })
}

pub async fn initialize<T: Send + 'static>(
    store: &mut Store<T>,
    instances: &GraphInstances,
    initialization: &GraphInitialization,
) -> error::Result<()> {
    let base_initialize =
        instances.modules[0].get_typed_func::<(), ()>(&mut *store, "_initialize")?;
    let base = instances.modules[0];
    wasmtime::error::Context::with_context(
        call_generated_graph_optional_0(store, base, "__wasm_apply_data_relocs").await,
        || "run data relocations for authenticated module graph role base (module index 0)",
    )?;
    wasmtime::error::Context::with_context(
        base_initialize.call_async(&mut *store, ()).await,
        || "run initializer for authenticated module graph role base (module index 0)",
    )?;
    for role in &initialization.relocation_order {
        let module_index = generated_graph_module_index(&initialization.module_order, role)
            .map_err(|error| WasmtimeError::msg(format!("{error:#}")))?;
        let instance = instances.modules[module_index];
        wasmtime::error::Context::with_context(
            call_generated_graph_optional_0(store, instance, "__wasm_apply_data_relocs").await,
            || {
                format!(
                    "run data relocations for authenticated module graph role {role} (module \
                     index {module_index})"
                )
            },
        )?;
    }
    for role in &initialization.constructor_order {
        let module_index = generated_graph_module_index(&initialization.module_order, role)
            .map_err(|error| WasmtimeError::msg(format!("{error:#}")))?;
        let instance = instances.modules[module_index];
        wasmtime::error::Context::with_context(
            call_generated_graph_required_0(store, instance, "__wasm_call_ctors").await,
            || {
                format!(
                    "run constructors for authenticated module graph role {role} (module index \
                     {module_index})"
                )
            },
        )?;
    }
    Ok(())
}

async fn prepare_generated_emscripten_memory_and_table<T: Send + 'static>(
    store: &mut Store<T>,
    base: Instance,
    memory: Memory,
    table: wasmtime::Table,
    initialization: &GraphInitialization,
) -> error::Result<()> {
    const WASM_PAGE_BYTES: u64 = 65_536;
    let required_pages = u64::from(initialization.final_memory_cursor).div_ceil(WASM_PAGE_BYTES);
    let current_pages = memory.size(&*store);
    if required_pages > current_pages {
        let previous = memory.grow(&mut *store, required_pages - current_pages)?;
        error::ensure!(
            previous == current_pages,
            "shared module graph memory grew from an unexpected page count"
        );
    }
    let sbrk = base
        .get_typed_func::<i32, i32>(&mut *store, "sbrk")
        .context("base module does not export the required sbrk boundary")?;
    let current_break = sbrk.call_async(&mut *store, 0).await?;
    let base_heap_base = i32::try_from(initialization.base_heap_base)?;
    error::ensure!(
        current_break == base_heap_base,
        "base sbrk cursor differs from authenticated __heap_base"
    );
    let allocation_bytes = initialization
        .final_memory_cursor
        .checked_sub(initialization.base_heap_base)
        .context("module graph final memory cursor precedes __heap_base")?;
    if allocation_bytes != 0 {
        let previous = sbrk
            .call_async(&mut *store, i32::try_from(allocation_bytes)?)
            .await?;
        error::ensure!(
            previous == base_heap_base,
            "base sbrk did not reserve the authenticated side-module range"
        );
    }
    let current_table_size = table.size(&*store);
    error::ensure!(
        initialization.final_table_cursor >= current_table_size,
        "module graph final table cursor precedes the base table"
    );
    let additional = initialization.final_table_cursor - current_table_size;
    if additional != 0 {
        let table_type = table.ty(&*store);
        let previous = table.grow(
            &mut *store,
            additional,
            Ref::null(table_type.element().heap_type()),
        )?;
        error::ensure!(
            previous == current_table_size,
            "shared module graph table grew from an unexpected size"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_generated_emscripten_side_imports<T>(
    store: &mut Store<T>,
    graph: &GraphModules,
    module_index: usize,
    module: &wasmtime::Module,
    instances: &[Instance],
    memory: Memory,
    table: wasmtime::Table,
    stack_pointer: Global,
    got: &mut GeneratedGraphGotBindings,
) -> error::Result<Vec<Extern>> {
    module
        .imports()
        .enumerate()
        .map(|(import_index, imported)| {
            let provider = &graph.modules[module_index].providers[import_index];
            error::ensure!(
                provider.import_index == import_index
                    && provider.imported_module == imported.module()
                    && provider.imported_name == imported.name(),
                "side-module import differs from its authenticated provider"
            );
            match provider.provider.as_str() {
                "loader" => {
                    let ExternType::Global(global_type) = imported.ty() else {
                        error::bail!("loader relocation base import is not a global")
                    };
                    let placement = &graph.modules[module_index].layout;
                    let value = match provider.imported_name.as_str() {
                        "__memory_base" => u64::from(placement.memory_base),
                        "__table_base" => placement.table_base,
                        _ => error::bail!("loader provider names an unsupported relocation base"),
                    };
                    Ok(
                        Global::new(&mut *store, global_type, Val::I32(i32::try_from(value)?))?
                            .into(),
                    )
                }
                "weak-zero" => {
                    let ExternType::Global(global_type) = imported.ty() else {
                        error::bail!("weak GOT import is not a global")
                    };
                    generated_emscripten_got_import(
                        store,
                        graph,
                        provider,
                        global_type,
                        instances,
                        table,
                        got,
                        false,
                    )
                }
                role if matches!(provider.imported_module.as_str(), "GOT.mem" | "GOT.func") => {
                    let provider_index =
                        generated_graph_module_index(&graph.initialization.module_order, role)?;
                    let ExternType::Global(global_type) = imported.ty() else {
                        error::bail!("GOT import is not a global")
                    };
                    generated_emscripten_got_import(
                        store,
                        graph,
                        provider,
                        global_type,
                        instances,
                        table,
                        got,
                        provider_index < module_index,
                    )
                }
                role => {
                    let provider_index =
                        generated_graph_module_index(&graph.initialization.module_order, role)?;
                    let provider_instance = instances
                        .get(provider_index)
                        .copied()
                        .context("side-module provider has not been instantiated")?;
                    let export_name = provider
                        .provider_export
                        .as_deref()
                        .context("side-module provider export is missing")?;
                    let external = provider_instance
                        .get_export(&mut *store, export_name)
                        .context("side-module provider export is unavailable")?;
                    match external {
                        Extern::Memory(_) => {
                            error::ensure!(provider_index == 0, "shared memory is not base-owned");
                            Ok(memory.into())
                        }
                        Extern::Table(_) => {
                            error::ensure!(provider_index == 0, "shared table is not base-owned");
                            Ok(table.into())
                        }
                        Extern::Global(_) if export_name == "__stack_pointer" => {
                            error::ensure!(
                                provider_index == 0,
                                "shared stack pointer is not base-owned"
                            );
                            Ok(stack_pointer.into())
                        }
                        external => Ok(external),
                    }
                }
            }
        })
        .collect()
}

fn generated_graph_module_index(module_order: &[String], role: &str) -> error::Result<usize> {
    module_order
        .iter()
        .position(|candidate| candidate.as_str() == role)
        .with_context(|| format!("module graph provider {role} is not an authenticated module"))
}

#[allow(clippy::too_many_arguments)]
fn generated_emscripten_got_import<T>(
    store: &mut Store<T>,
    graph: &GraphModules,
    provider: &GraphModuleProvider,
    global_type: GlobalType,
    instances: &[Instance],
    table: wasmtime::Table,
    got: &mut GeneratedGraphGotBindings,
    populate: bool,
) -> error::Result<Extern> {
    let key = (
        provider.imported_module.clone(),
        provider.imported_name.clone(),
    );
    if let Some(binding) = got.get(&key) {
        error::ensure!(
            binding.provider == provider.provider
                && binding.provider_export == provider.provider_export
                && binding.weak == provider.weak,
            "shared GOT symbol has conflicting authenticated providers"
        );
        return Ok(binding.global.into());
    }
    error::ensure!(
        matches!(global_type.content(), wasmtime::ValType::I32)
            && global_type.mutability() == wasmtime::Mutability::Var,
        "GOT import is not a mutable i32 global"
    );
    let global = Global::new(&mut *store, global_type, Val::I32(0))?;
    got.insert(
        key,
        GeneratedGraphGotBinding {
            global,
            provider: provider.provider.clone(),
            provider_export: provider.provider_export.clone(),
            weak: provider.weak,
        },
    );
    if populate {
        populate_generated_emscripten_got(
            store,
            &graph.initialization.module_order,
            provider,
            instances,
            table,
            global,
        )?;
    }
    Ok(global.into())
}

fn populate_generated_emscripten_got<T>(
    store: &mut Store<T>,
    module_order: &[String],
    provider: &GraphModuleProvider,
    instances: &[Instance],
    table: wasmtime::Table,
    global: Global,
) -> error::Result<()> {
    if provider.weak {
        return Ok(());
    }
    let provider_index = generated_graph_module_index(module_order, &provider.provider)?;
    let instance = instances
        .get(provider_index)
        .copied()
        .context("GOT provider is unavailable")?;
    let export_name = provider
        .provider_export
        .as_deref()
        .context("strong GOT provider export is missing")?;
    let external = instance
        .get_export(&mut *store, export_name)
        .context("strong GOT provider export is unavailable")?;
    let value = match provider.imported_module.as_str() {
        "GOT.mem" => external
            .into_global()
            .context("GOT.mem provider export is not a global")?
            .get(&mut *store)
            .i32()
            .context("GOT.mem provider export is not i32")?,
        "GOT.func" => {
            let function = external
                .into_func()
                .context("GOT.func provider export is not a function")?;
            let index = table.size(&*store);
            let table_type = table.ty(&*store);
            let previous =
                table.grow(&mut *store, 1, Ref::null(table_type.element().heap_type()))?;
            error::ensure!(previous == index, "GOT function table allocation changed");
            table.set(&mut *store, index, function.into())?;
            i32::try_from(index)?
        }
        _ => error::bail!("GOT provider uses an unsupported namespace"),
    };
    global.set(&mut *store, Val::I32(value))?;
    Ok(())
}

fn update_generated_emscripten_self_got<T>(
    store: &mut Store<T>,
    graph: &GraphModules,
    module_index: usize,
    table: wasmtime::Table,
    got: &mut GeneratedGraphGotBindings,
    instances: &[Instance],
) -> error::Result<()> {
    for provider in graph.modules[module_index]
        .providers
        .iter()
        .filter(|provider| {
            provider.provider == provider.consumer
                && matches!(provider.imported_module.as_str(), "GOT.mem" | "GOT.func")
        })
    {
        let key = (
            provider.imported_module.clone(),
            provider.imported_name.clone(),
        );
        let global = got
            .get(&key)
            .context("self GOT provider has no loader-created global")?
            .global;
        populate_generated_emscripten_got(
            store,
            &graph.initialization.module_order,
            provider,
            instances,
            table,
            global,
        )?;
    }
    Ok(())
}

fn reject_unresolved_generated_emscripten_got<T>(
    store: &mut Store<T>,
    graph: &GraphModules,
    got: &GeneratedGraphGotBindings,
) -> error::Result<()> {
    let expected = graph.modules[1..]
        .iter()
        .flat_map(|module| &module.providers)
        .filter(|provider| matches!(provider.imported_module.as_str(), "GOT.mem" | "GOT.func"))
        .map(|provider| {
            (
                provider.imported_module.clone(),
                provider.imported_name.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    error::ensure!(
        expected.len() == got.len() && expected.iter().all(|key| got.contains_key(key)),
        "loader GOT set differs from authenticated providers"
    );
    for ((namespace, name), binding) in got {
        let value = binding
            .global
            .get(&mut *store)
            .i32()
            .context("loader GOT global is not i32")?;
        error::ensure!(
            (binding.weak && value == 0) || (!binding.weak && value != 0),
            "loader GOT symbol {namespace}.{name} has an invalid resolved value"
        );
    }
    Ok(())
}

async fn call_generated_graph_optional_0<T: Send + 'static>(
    store: &mut Store<T>,
    instance: Instance,
    name: &str,
) -> Result<(), WasmtimeError> {
    if let Some(function) = instance.get_func(&mut *store, name) {
        function
            .typed::<(), ()>(&*store)?
            .call_async(&mut *store, ())
            .await?;
    }
    Ok(())
}

async fn call_generated_graph_required_0<T: Send + 'static>(
    store: &mut Store<T>,
    instance: Instance,
    name: &str,
) -> Result<(), WasmtimeError> {
    instance
        .get_typed_func::<(), ()>(&mut *store, name)?
        .call_async(&mut *store, ())
        .await?;
    Ok(())
}
