//! Local initialization measurements for authenticated graph packages.
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

use convex_wasm_precompiler::{
    capability_replay_host::{Case, State, add_imports},
    graph_initialization::{
        self, GraphInitialization, GraphModule, GraphModuleLayout, GraphModuleProvider,
        GraphModules,
    },
    wasmtime_wasi::add_wasi_imports,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasmtime::{
    Config, Engine, Linker, Memory, Module, Store, TypedFunc, UpdateDeadline,
    error::{self, Context as _, ensure},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    environment: BTreeMap<String, Option<String>>,
    fuel: u64,
    fuel_epoch_poll_interval: u64,
    repetitions: usize,
    preparation_mode: PreparationMode,
    cpu: usize,
    graphs: Vec<Graph>,
    #[serde(default)]
    scenarios: Vec<PoolScenario>,
    #[serde(default)]
    initialization_trace: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PoolScenario {
    name: String,
    worker_cpus: Vec<usize>,
    instances: Vec<PoolInstances>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolInstances {
    graph: String,
    count: usize,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum PreparationMode {
    AllEntries,
    EachEntry,
    ValidateReset,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Graph {
    name: String,
    initialization: GraphInitialization,
    modules: Vec<ModuleInput>,
    entries: Vec<Entry>,
    // A mixed control/instrumented comparison overrides the input-wide default.
    initialization_trace: Option<bool>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    name: String,
    selector_hex: String,
}

struct InitializationTraceRecord {
    kind: i32,
    unit: i32,
    parent: i32,
    finished: i32,
    wall_start: u64,
    cpu_start: u64,
    wall_end: u64,
    cpu_end: u64,
    heap_before: [u64; 5],
    heap_after: [u64; 5],
}

struct PreparedInstance {
    graph: String,
    entries: Vec<Entry>,
    store: Store<State>,
    memory: Memory,
    select: TypedFunc<i64, i32>,
    prepare: TypedFunc<(), i32>,
    diagnostics: Option<TypedFunc<i32, i32>>,
    rows: Vec<Value>,
    instantiate_ms: f64,
    native_initialize_ms: f64,
    first_elapsed_ms: f64,
    ready_elapsed_ms: f64,
    ready_cpu_ms: f64,
}

impl PreparedInstance {
    async fn validate_reset(mut self, input: &Input, iteration: usize) -> error::Result<()> {
        let diagnostics = self
            .diagnostics
            .clone()
            .context("reset validation requires an initialization trace")?;
        let first_count = diagnostics.call_async(&mut self.store, 2).await?;
        ensure!(first_count > 0, "initial preparation produced no trace");
        for index in 0..self.entries.len() {
            self.measure_entry(input, index, iteration, 1).await?;
        }
        ensure!(
            diagnostics.call_async(&mut self.store, 2).await? == first_count,
            "prepared entry recheck repeated initialization"
        );

        // Preparation must reject invocation authority even for a cached entry.
        // Exercising the last entry after preparing every slot also covers handles
        // above the legacy fixed-size entry array when given a larger graph.
        let selector = u64::from_str_radix(
            &self
                .entries
                .last()
                .context("reset validation has no entries")?
                .selector_hex,
            16,
        )?;
        self.store.data_mut().begin(&Case {
            selector,
            timestamp_ms: 0.0,
            args: json!({}),
            expected: Value::Null,
            replay: serde_json::from_value(
                json!({"epochs":[{"reads":[],"write":null}],"calls":0}),
            )?,
            entropy: Vec::new(),
        })?;
        self.store.set_fuel(input.fuel)?;
        ensure!(
            self.select
                .call_async(&mut self.store, selector as i64)
                .await?
                == 0,
            "reset validation entry selection failed"
        );
        let rejected_status = self.prepare.call_async(&mut self.store, ()).await?;
        ensure!(
            rejected_status == 68,
            "preparation did not reject invocation authority: {rejected_status}"
        );

        // No handler ran. Restore a preparation-only host while retaining the same
        // Store, memory and native module instances; the guest must recreate its heap.
        *self.store.data_mut() = State::new(input.environment.clone());
        for index in (0..self.entries.len()).rev() {
            self.measure_entry(input, index, iteration, 2).await?;
        }
        let second_count = diagnostics.call_async(&mut self.store, 2).await?;
        ensure!(
            second_count == first_count * 2,
            "reset did not repeat the full initialization inventory"
        );
        for index in 0..self.entries.len() {
            self.measure_entry(input, index, iteration, 3).await?;
        }
        ensure!(
            diagnostics.call_async(&mut self.store, 2).await? == second_count,
            "entry recheck after reset repeated initialization"
        );
        self.read_initialization_trace().await?;
        let mut inventories = [BTreeMap::new(), BTreeMap::new()];
        for row in &self.rows {
            if row["phase"] != "logicalInitialization" {
                continue;
            }
            let index = row["index"].as_i64().context("trace index is missing")?;
            let key = (
                row["kind"].as_i64().context("trace kind is missing")?,
                row["unitSlot"].as_i64().context("trace unit is missing")?,
            );
            *inventories[usize::from(index >= i64::from(first_count))]
                .entry(key)
                .or_insert(0usize) += 1;
        }
        ensure!(
            inventories[0] == inventories[1],
            "reset changed the initializer inventory"
        );
        for mut row in self.rows {
            row["iteration"] = json!(iteration);
            row["validation"] = json!("reset");
            println!("{row}");
        }
        println!(
            "{}",
            json!({"phase":"resetValidationComplete","graph":self.graph,
            "iteration":iteration,"entries":self.entries.len(),"rejectedStatus":rejected_status,
            "initialTraceRecords":first_count,"finalTraceRecords":second_count})
        );
        Ok(())
    }

    async fn measure_entry(
        &mut self,
        input: &Input,
        index: usize,
        iteration: usize,
        pass: usize,
    ) -> error::Result<f64> {
        let entry = &self.entries[index];
        let selector = u64::from_str_radix(&entry.selector_hex, 16)? as i64;
        self.store.set_fuel(input.fuel)?;
        let cpu_started = thread_cpu_seconds()?;
        let before_memory = self.memory.data_size(&self.store);
        let started = Instant::now();
        ensure!(
            self.select.call_async(&mut self.store, selector).await? == 0,
            "entry selection failed"
        );
        let status = self.prepare.call_async(&mut self.store, ()).await?;
        ensure!(
            status == 0,
            "entry preparation failed: graph {}, entry {}, pass {}, status {}",
            self.graph,
            entry.name,
            pass,
            status
        );
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let cpu_ms = (thread_cpu_seconds()? - cpu_started) * 1000.0;
        self.rows.push(json!({"phase":"entryPreparation","graph":self.graph,
            "iteration":iteration,"pass":pass,"entry":entry.name,
            "elapsedMs":elapsed_ms,"cpuMs":cpu_ms,
            "fuelConsumed":input.fuel.checked_sub(self.store.get_fuel()?).context("fuel increased")?,
            "linearMemoryBefore":before_memory,"linearMemoryAfter":self.memory.data_size(&self.store),
            "reportedGcCounters":self.store.data().gc,
            "configurationReadNames":self.store.data().environment_reads.keys().collect::<Vec<_>>() }));
        if let Some(diagnostics) = &self.diagnostics {
            let count = diagnostics.call_async(&mut self.store, 2).await?;
            self.rows
                .last_mut()
                .context("entry measurement is absent")?["initializationTraceEndIndex"] =
                json!(count);
        }
        Ok(elapsed_ms)
    }

    async fn read_initialization_trace(&mut self) -> error::Result<()> {
        let Some(diagnostics) = &self.diagnostics else {
            return Ok(());
        };
        let version = diagnostics.call_async(&mut self.store, 0).await?;
        let stride = diagnostics.call_async(&mut self.store, 3).await?;
        let count = diagnostics.call_async(&mut self.store, 2).await?;
        ensure!(
            version == 1 && stride == 128 && (0..=4096).contains(&count),
            "unsupported initialization trace layout"
        );
        let pointer = diagnostics.call_async(&mut self.store, 1).await? as u32 as usize;
        let bytes = self
            .memory
            .data(&self.store)
            .get(pointer..pointer + count as usize * 128)
            .context("initialization trace lies outside guest memory")?;
        let records = bytes
            .chunks_exact(128)
            .map(|record| {
                let i32_at =
                    |offset| i32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
                let u64_at =
                    |offset| u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap());
                InitializationTraceRecord {
                    kind: i32_at(0),
                    unit: i32_at(4),
                    parent: i32_at(8),
                    finished: i32_at(12),
                    wall_start: u64_at(16),
                    cpu_start: u64_at(24),
                    wall_end: u64_at(32),
                    cpu_end: u64_at(40),
                    heap_before: std::array::from_fn(|i| u64_at(48 + i * 8)),
                    heap_after: std::array::from_fn(|i| u64_at(88 + i * 8)),
                }
            })
            .collect::<Vec<_>>();
        let mut children = vec![(0u64, 0u64); records.len()];
        for (index, record) in records.iter().enumerate() {
            ensure!(
                (1..=7).contains(&record.kind)
                    && record.finished == 1
                    && record.parent >= -1
                    && record.parent < index as i32,
                "invalid initialization trace record"
            );
            let wall = record
                .wall_end
                .checked_sub(record.wall_start)
                .context("trace wall clock moved backward")?;
            let cpu = record
                .cpu_end
                .checked_sub(record.cpu_start)
                .context("trace CPU clock moved backward")?;
            if record.parent >= 0 {
                let parent = &records[record.parent as usize];
                ensure!(
                    record.wall_start >= parent.wall_start
                        && record.wall_end <= parent.wall_end
                        && record.cpu_start >= parent.cpu_start
                        && record.cpu_end <= parent.cpu_end,
                    "trace child is outside parent interval"
                );
                children[record.parent as usize].0 += wall;
                children[record.parent as usize].1 += cpu;
            }
        }
        for (index, record) in records.into_iter().enumerate() {
            let wall = record.wall_end - record.wall_start;
            let cpu = record.cpu_end - record.cpu_start;
            self.rows.push(json!({"phase":"logicalInitialization","graph":self.graph,
                "index":index,"kind":record.kind,"unitSlot":record.unit,"parent":record.parent,
                "inclusiveWallNanos":wall,"inclusiveCpuNanos":cpu,
                "exclusiveWallNanos":wall.checked_sub(children[index].0).context("trace children overlap")?,
                "exclusiveCpuNanos":cpu.checked_sub(children[index].1).context("trace child CPU exceeds parent")?,
                "heapBefore":heap_statistics(record.heap_before),"heapAfter":heap_statistics(record.heap_after)}));
        }
        let heap_pointer = diagnostics.call_async(&mut self.store, 4).await? as u32 as usize;
        let heap = self
            .memory
            .data(&self.store)
            .get(heap_pointer..heap_pointer + 40)
            .context("heap snapshot lies outside guest memory")?;
        let counters = std::array::from_fn::<_, 5, _>(|i| {
            u64::from_le_bytes(heap[i * 8..i * 8 + 8].try_into().unwrap())
        });
        self.rows.push(json!({"phase":"initializationHeap","graph":self.graph,"heap":heap_statistics(counters)}));
        Ok(())
    }

    async fn report(
        mut self,
        input: &Input,
        iteration: usize,
        scenario: Option<&str>,
        instance: usize,
    ) -> error::Result<()> {
        let initial_trace_count = match &self.diagnostics {
            Some(diagnostics) => Some(diagnostics.call_async(&mut self.store, 2).await?),
            None => None,
        };
        self.read_initialization_trace().await?;
        let started = Instant::now();
        let cpu_started = thread_cpu_seconds()?;
        let mut recheck_ms = 0.0;
        for index in 0..self.entries.len() {
            recheck_ms += self.measure_entry(input, index, iteration, 1).await?;
        }
        let elapsed_with_recheck_ms =
            self.ready_elapsed_ms + started.elapsed().as_secs_f64() * 1000.0;
        let cpu_with_recheck_ms =
            self.ready_cpu_ms + (thread_cpu_seconds()? - cpu_started) * 1000.0;
        if let Some(diagnostics) = &self.diagnostics {
            ensure!(
                Some(diagnostics.call_async(&mut self.store, 2).await?) == initial_trace_count,
                "prepared entry recheck repeated initialization"
            );
        }
        for mut row in self.rows {
            row["iteration"] = json!(iteration);
            row["scenario"] = json!(scenario);
            row["instance"] = json!(instance);
            println!("{row}");
        }
        println!(
            "{}",
            json!({"phase":"groupComplete","graph":self.graph,
            "iteration":iteration,"scenario":scenario,"instance":instance,
            "instantiateMs":self.instantiate_ms,"nativeInitializeMs":self.native_initialize_ms,
            "firstPreparationMs":self.first_elapsed_ms,"readyElapsedMs":self.ready_elapsed_ms,
            "readyCpuMs":self.ready_cpu_ms,"recheckMs":recheck_ms,
            "elapsedWithRecheckMs":elapsed_with_recheck_ms,"cpuWithRecheckMs":cpu_with_recheck_ms,
            "linearMemoryBytes":self.memory.data_size(&self.store),
            "entries":self.entries.len(),"firstEntry":self.entries[0].name})
        );
        Ok(())
    }
}

fn heap_statistics(counters: [u64; 5]) -> Value {
    json!({"collections":counters[0],"allocatedBytes":counters[1],"heapBytes":counters[2],
        "gcWallNanos":counters[3],"gcCpuNanos":counters[4]})
}

async fn initialize_instance(
    engine: &Engine,
    input: &Input,
    graph: &Graph,
    prepared: &GraphModules,
    entries: &[Entry],
    iteration: usize,
) -> error::Result<PreparedInstance> {
    let started = Instant::now();
    let cpu_started = thread_cpu_seconds()?;
    let mut linker = Linker::new(engine);
    add_wasi_imports(&mut linker)?;
    add_imports(&mut linker, &prepared.modules[0].module)?;
    linker.define_unknown_imports_as_traps(&prepared.modules[0].module)?;
    let mut store = Store::new(engine, State::new(input.environment.clone()));
    store.set_fuel(input.fuel)?;
    store.epoch_deadline_callback(|_| Ok(UpdateDeadline::Yield(1)));
    store.set_epoch_deadline(1);
    let instances = graph_initialization::instantiate(&linker, &mut store, prepared).await?;
    let instantiate_ms = started.elapsed().as_secs_f64() * 1000.0;
    let base = instances.modules[0];
    let native_started = Instant::now();
    graph_initialization::initialize(&mut store, &instances, &prepared.initialization).await?;
    let native_initialize_ms = native_started.elapsed().as_secs_f64() * 1000.0;
    let memory = base
        .get_memory(&mut store, "memory")
        .context("base memory is missing")?;
    let select = base.get_typed_func::<i64, i32>(&mut store, "convex_wasm_graph_select_entry")?;
    let prepare =
        base.get_typed_func::<(), i32>(&mut store, "convex_wasm_udf_prepare_selected_entry")?;
    let diagnostics = if graph
        .initialization_trace
        .unwrap_or(input.initialization_trace)
    {
        Some(base.get_typed_func::<i32, i32>(&mut store, "convex_wasm_initialization_diagnostics")?)
    } else {
        ensure!(
            base.get_func(&mut store, "convex_wasm_initialization_diagnostics")
                .is_none(),
            "instrumented package requires initializationTrace=true"
        );
        None
    };
    let mut result = PreparedInstance {
        graph: graph.name.clone(),
        entries: entries.to_vec(),
        store,
        memory,
        select,
        prepare,
        diagnostics,
        rows: Vec::new(),
        instantiate_ms,
        native_initialize_ms,
        first_elapsed_ms: 0.0,
        ready_elapsed_ms: 0.0,
        ready_cpu_ms: 0.0,
    };
    for index in 0..entries.len() {
        result.first_elapsed_ms += result.measure_entry(input, index, iteration, 0).await?;
    }
    result.ready_elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    result.ready_cpu_ms = (thread_cpu_seconds()? - cpu_started) * 1000.0;
    Ok(result)
}

fn resident_bytes() -> error::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/statm")?;
    let pages: u64 = status
        .split_whitespace()
        .nth(1)
        .context("resident page count is absent")?
        .parse()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page_size > 0, "system page size is invalid");
    pages
        .checked_mul(page_size as u64)
        .context("resident byte count overflowed")
}

fn measure_pool(
    engine: &Engine,
    input: &Input,
    prepared: &[GraphModules],
    scenario: &PoolScenario,
    iteration: usize,
) -> error::Result<()> {
    ensure!(
        !scenario.name.is_empty() && !scenario.worker_cpus.is_empty(),
        "pool scenario requires a name and worker CPUs"
    );
    ensure!(
        scenario
            .worker_cpus
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == scenario.worker_cpus.len(),
        "pool workers must use distinct CPUs"
    );
    let by_name = input
        .graphs
        .iter()
        .enumerate()
        .map(|(index, graph)| (graph.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        by_name.len() == input.graphs.len(),
        "graph names must be unique for pool selection"
    );
    let mut tasks = Vec::new();
    for requested in &scenario.instances {
        let index = *by_name
            .get(requested.graph.as_str())
            .context("pool references an unknown graph")?;
        ensure!(requested.count > 0, "pool instance count must be positive");
        tasks.extend(std::iter::repeat_n(index, requested.count));
    }
    ensure!(!tasks.is_empty(), "pool must prepare at least one instance");
    let rotation = iteration % tasks.len();
    tasks.rotate_left(rotation);
    let next = AtomicUsize::new(0);
    let sampling = Arc::new(AtomicBool::new(true));
    let sampler_running = Arc::clone(&sampling);
    let before_rss = resident_bytes()?;
    let sampler = std::thread::spawn(move || -> error::Result<u64> {
        let mut peak = before_rss;
        while sampler_running.load(Ordering::Relaxed) {
            peak = peak.max(resident_bytes()?);
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(peak)
    });
    let started = Instant::now();
    let result = std::thread::scope(|scope| -> error::Result<Vec<(usize, PreparedInstance)>> {
        let mut workers = Vec::new();
        for &cpu in &scenario.worker_cpus {
            let tasks = &tasks;
            let next = &next;
            workers.push(
                scope.spawn(move || -> error::Result<Vec<(usize, PreparedInstance)>> {
                    pin_cpu(cpu)?;
                    let mut instances = Vec::new();
                    loop {
                        let task = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&index) = tasks.get(task) else { break };
                        let graph = &input.graphs[index];
                        instances.push((
                            task,
                            finish(initialize_instance(
                                engine,
                                input,
                                graph,
                                &prepared[index],
                                &graph.entries,
                                iteration,
                            ))?,
                        ));
                    }
                    // Returning the Stores keeps every prepared heap alive until all workers finish.
                    Ok(instances)
                }),
            );
        }
        let mut instances = Vec::new();
        for worker in workers {
            instances.extend(
                worker
                    .join()
                    .map_err(|_| error::format_err!("preparation worker panicked"))??,
            );
        }
        Ok(instances)
    });
    let ready_ms = started.elapsed().as_secs_f64() * 1000.0;
    sampling.store(false, Ordering::Relaxed);
    let peak_rss = sampler
        .join()
        .map_err(|_| error::format_err!("memory sampler panicked"))??;
    let mut instances = result?;
    instances.sort_by_key(|(task, _)| *task);
    ensure!(
        instances.len() == tasks.len(),
        "pool lost prepared instances"
    );
    let ready_rss = resident_bytes()?;
    let linear_bytes: usize = instances
        .iter()
        .map(|(_, instance)| instance.memory.data_size(&instance.store))
        .sum();
    let cpu_ms: f64 = instances
        .iter()
        .map(|(_, instance)| instance.ready_cpu_ms)
        .sum();
    println!(
        "{}",
        json!({"phase":"poolReady","scenario":scenario.name,"iteration":iteration,
        "instances":instances.len(),"workers":scenario.worker_cpus.len(),"elapsedMs":ready_ms,
        "preparationCpuMs":cpu_ms,"linearMemoryBytes":linear_bytes,
        "residentBeforeBytes":before_rss,"residentReadyBytes":ready_rss,
        "sampledPeakResidentBytes":peak_rss.max(ready_rss),"memorySampleIntervalMs":5})
    );
    pin_cpu(input.cpu)?;
    for (task, instance) in instances {
        finish(instance.report(input, iteration, Some(&scenario.name), task))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModuleInput {
    role: String,
    layout: GraphModuleLayout,
    providers: Vec<GraphModuleProvider>,
    aot: Artifact,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
    size: usize,
}

struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn finish<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn thread_cpu_seconds() -> error::Result<f64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // This clock measures the execution thread, independently of the epoch ticker.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) };
    ensure!(
        status == 0,
        "thread CPU clock failed: {}",
        std::io::Error::last_os_error()
    );
    let value = unsafe { value.assume_init() };
    Ok(value.tv_sec as f64 + value.tv_nsec as f64 * 1e-9)
}

fn pin_cpu(cpu: usize) -> error::Result<()> {
    #[cfg(target_os = "linux")]
    {
        ensure!(
            cpu < libc::CPU_SETSIZE as usize,
            "CPU index exceeds affinity capacity"
        );
        let mut affinity = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
        unsafe { libc::CPU_SET(cpu, &mut affinity) };
        ensure!(
            unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity) } == 0,
            "unable to set execution affinity: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu;
        error::bail!("explicit CPU affinity is supported only on Linux");
    }
}

async fn measure(engine: &Engine, input: &Input) -> error::Result<()> {
    ensure!(
        input.repetitions > 0 && input.fuel > 0 && !input.graphs.is_empty(),
        "initialization input must select graphs, fuel and repetitions"
    );
    let mut cache = BTreeMap::<String, Arc<Module>>::new();
    let mut prepared = Vec::new();
    let load_started = Instant::now();
    for graph in &input.graphs {
        ensure!(
            graph.modules.len() == graph.initialization.module_order.len()
                && graph
                    .modules
                    .iter()
                    .zip(&graph.initialization.module_order)
                    .all(|(m, r)| &m.role == r),
            "module order differs from graph initialization"
        );
        ensure!(
            graph.modules.first().is_some_and(|m| m.role == "base")
                && graph.modules.last().is_some_and(|m| m.role == "leaf")
                && !graph.entries.is_empty(),
            "graph must have a base, leaf and entries"
        );
        let mut modules = Vec::new();
        for record in &graph.modules {
            let module = if let Some(module) = cache.get(&record.aot.sha256) {
                Arc::clone(module)
            } else {
                let started = Instant::now();
                let bytes = std::fs::read(&record.aot.path)?;
                ensure!(
                    bytes.len() == record.aot.size
                        && format!("{:x}", Sha256::digest(&bytes)) == record.aot.sha256,
                    "AOT differs from verified package receipt"
                );
                let authenticated_ms = started.elapsed().as_secs_f64() * 1000.0;
                let decode_started = Instant::now();
                // Only use inputs produced by the package verifier and a trusted native
                // compiler. A digest alone cannot make an arbitrary native image safe.
                let module = Arc::new(unsafe { Module::deserialize(engine, bytes)? });
                println!(
                    "{}",
                    json!({"phase":"aotLoad","sha256":record.aot.sha256,
                    "authenticationMs":authenticated_ms,
                    "deserializeMs":decode_started.elapsed().as_secs_f64()*1000.0})
                );
                cache.insert(record.aot.sha256.clone(), Arc::clone(&module));
                module
            };
            ensure!(
                module.imports().len() == record.providers.len(),
                "provider count differs from module imports"
            );
            modules.push(GraphModule {
                module,
                layout: record.layout.clone(),
                providers: record.providers.clone(),
            });
        }
        prepared.push(GraphModules {
            modules,
            initialization: graph.initialization.clone(),
        });
    }
    println!(
        "{}",
        json!({"phase":"allAotLoaded","uniqueModules":cache.len(),
        "elapsedMs":load_started.elapsed().as_secs_f64()*1000.0})
    );
    if !input.scenarios.is_empty() {
        ensure!(
            matches!(input.preparation_mode, PreparationMode::AllEntries),
            "pool scenarios require complete entry preparation"
        );
        for iteration in 0..input.repetitions {
            for offset in 0..input.scenarios.len() {
                let index = (iteration + offset) % input.scenarios.len();
                measure_pool(engine, input, &prepared, &input.scenarios[index], iteration)?;
            }
        }
    } else {
        pin_cpu(input.cpu)?;
        for iteration in 0..input.repetitions {
            for offset in 0..input.graphs.len() {
                let index = (offset + iteration) % input.graphs.len();
                let graph = &input.graphs[index];
                let batches: Vec<&[Entry]> = match input.preparation_mode {
                    PreparationMode::AllEntries | PreparationMode::ValidateReset => {
                        vec![graph.entries.as_slice()]
                    }
                    PreparationMode::EachEntry => graph.entries.chunks(1).collect(),
                };
                for (batch, entries) in batches.into_iter().enumerate() {
                    let instance = initialize_instance(
                        engine,
                        input,
                        graph,
                        &prepared[index],
                        entries,
                        iteration,
                    )
                    .await?;
                    if matches!(input.preparation_mode, PreparationMode::ValidateReset) {
                        instance.validate_reset(input, iteration).await?;
                    } else {
                        instance.report(input, iteration, None, batch).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() -> error::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input_path = args
        .next()
        .context("usage: convex-wasm-graph-initialization VERIFIED_INPUT.json")?;
    ensure!(
        args.next().is_none(),
        "unexpected initialization runner argument"
    );
    let input: Input = serde_json::from_slice(&std::fs::read(input_path)?)?;
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_exceptions(true)
        .fuel_epoch_poll_interval(input.fuel_epoch_poll_interval);
    let engine = Engine::new(&config)?;
    let running = Arc::new(AtomicBool::new(true));
    let ticker_engine = engine.clone();
    let ticker_running = Arc::clone(&running);
    let ticker = std::thread::spawn(move || {
        while ticker_running.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
            ticker_engine.increment_epoch();
        }
    });
    let result = finish(measure(&engine, &input));
    running.store(false, Ordering::Relaxed);
    ticker
        .join()
        .map_err(|_| error::format_err!("epoch ticker panicked"))?;
    result
}
