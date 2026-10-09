use std::{
    collections::BTreeMap,
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use convex_wasm_precompiler::{
    capability_replay_host::{Case, State, add_imports},
    wasmtime_wasi::add_wasi_imports,
};
use serde::Deserialize;
use serde_json::json;
use wasmtime::{Config, Engine, Error, Instance, Linker, Module, ProfilingStrategy, Store};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    environment: BTreeMap<String, Option<String>>,
    cases: Vec<Case>,
    warmup: usize,
    repetitions: usize,
    fuel: u64,
    cpu: Option<usize>,
    #[serde(default)]
    perf_map: bool,
    #[serde(default)]
    paced: bool,
}

struct Guest {
    store: Store<State>,
    instance: Instance,
}

fn status(value: i32, phase: &str) -> Result<(), Error> {
    if value != 0 {
        return Err(Error::msg(format!(
            "Replay {phase} returned status {value}"
        )));
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err(Error::msg(
            "usage: convex-wasm-capability-replay TRACE.json BASELINE.wasm [CANDIDATE.wasm]",
        ));
    }
    let input: Input = serde_json::from_slice(&std::fs::read(&arguments[0])?)
        .map_err(|_| Error::msg("Invalid capability replay input"))?;
    if input.cases.is_empty()
        || input.warmup > 32
        || !(1..=if input.perf_map { 1024 } else { 256 }).contains(&input.repetitions)
        || input.fuel == 0
    {
        return Err(Error::msg("Invalid capability replay limits"));
    }
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_exceptions(true);
    if input.perf_map {
        config.profiler(ProfilingStrategy::PerfMap);
    }
    let engine = Engine::new(&config)?;
    let running = Arc::new(AtomicBool::new(true));
    let ticker = {
        let running = running.clone();
        let engine = engine.clone();
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
                engine.increment_epoch();
            }
        })
    };
    let result = run(&engine, &arguments[1..], &input);
    running.store(false, Ordering::Relaxed);
    ticker
        .join()
        .map_err(|_| Error::msg("Replay epoch ticker panicked"))?;
    result
}

fn run(engine: &Engine, paths: &[std::ffi::OsString], input: &Input) -> Result<(), Error> {
    let mut guests = Vec::new();
    for path in paths {
        let module = Module::from_file(engine, path)?;
        let mut linker = Linker::new(engine);
        add_wasi_imports(&mut linker)?;
        add_imports(&mut linker, &module)?;
        linker.define_unknown_imports_as_traps(&module)?;
        let mut store = Store::new(engine, State::new(input.environment.clone()));
        store.set_fuel(input.fuel)?;
        store.set_epoch_deadline(6000);
        let instance = linker.instantiate(&mut store, &module)?;
        instance
            .get_typed_func::<(), ()>(&mut store, "_initialize")?
            .call(&mut store, ())?;
        for case in &input.cases {
            store.set_fuel(input.fuel)?;
            store.set_epoch_deadline(6000);
            let select =
                instance.get_typed_func::<i64, i32>(&mut store, "convex_wasm_select_entry")?;
            status(select.call(&mut store, case.selector as i64)?, "selection")?;
            let prepare = instance
                .get_typed_func::<(), i32>(&mut store, "convex_wasm_udf_prepare_selected_entry")?;
            status(prepare.call(&mut store, ())?, "preparation")?;
        }
        guests.push(Guest { store, instance });
    }
    // Pin only execution: module compilation can use the host's available CPUs.
    if let Some(cpu) = input.cpu {
        #[cfg(target_os = "linux")]
        {
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(Error::msg("Replay CPU index exceeds affinity set size"));
            }
            let mut affinity = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            unsafe { libc::CPU_SET(cpu, &mut affinity) };
            if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity) }
                != 0
            {
                return Err(Error::msg(format!(
                    "Unable to set replay CPU affinity: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cpu;
            return Err(Error::msg("Replay CPU affinity requires Linux"));
        }
    }
    if input.paced {
        println!("{}", json!({"ready": true}));
        std::io::stdout().flush()?;
    }
    for repetition in 0..(input.warmup + input.repetitions) {
        // Alternate in the same process; source/module preparation stays
        // outside the measured interval and each variant retains its instance.
        let order: Vec<_> = if repetition % 2 == 0 {
            (0..guests.len()).collect()
        } else {
            (0..guests.len()).rev().collect()
        };
        for (case_index, case) in input.cases.iter().enumerate() {
            for &variant in &order {
                if input.paced {
                    // An external driver can interleave another engine while
                    // keeping both instances warm. IPC stays outside timing.
                    let mut command = [0; 4];
                    std::io::stdin().read_exact(&mut command)?;
                    if command != *b"run\n" {
                        return Err(Error::msg("Invalid paced replay command"));
                    }
                }
                let Guest { store, instance } = &mut guests[variant];
                let select =
                    instance.get_typed_func::<i64, i32>(&mut *store, "convex_wasm_select_entry")?;
                let invoke =
                    instance.get_typed_func::<(), i32>(&mut *store, "convex_wasm_udf_run")?;
                // Preparing another module may outlast this store's old deadline.
                store.set_fuel(input.fuel)?;
                store.set_epoch_deadline(6000);
                status(select.call(&mut *store, case.selector as i64)?, "selection")?;
                store.data_mut().begin(case)?;
                store.set_fuel(input.fuel)?;
                store.set_epoch_deadline(6000);
                let started = Instant::now();
                status(invoke.call(&mut *store, ())?, "handler")?;
                let elapsed = started.elapsed();
                let fuel = input.fuel - store.get_fuel()?;
                let captured_calls = store.data_mut().finish(case)?;
                let state = store.data();
                let guest_and_wasi = elapsed
                    .checked_sub(state.host_time)
                    .ok_or_else(|| Error::msg("Replay timing interval is inconsistent"))?;
                println!(
                    "{}",
                    json!({"variant": variant, "case": case_index,
                    "iteration": repetition, "warmup": repetition < input.warmup,
                    "elapsedMs": elapsed.as_secs_f64() * 1000.0,
                    "convexHostMs": state.host_time.as_secs_f64() * 1000.0,
                    "guestIncludingWasiMs": guest_and_wasi.as_secs_f64() * 1000.0,
                    "fuelConsumed": fuel, "capturedSdkCalls": captured_calls,
                    "hostCalls": state.host_calls, "consoleCalls": state.console_calls,
                    "objectLayouts": state.object_layouts, "gc": state.gc,
                    "outputMatches": true})
                );
                if input.paced {
                    std::io::stdout().flush()?;
                }
            }
        }
    }
    Ok(())
}
