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
use wasmtime::{
    Config, Engine, Error, Inlining, Instance, Linker, Module, ProfilingStrategy, Store,
};

#[derive(Clone, Copy)]
enum EngineVariant {
    Metered,
    FuelOnly,
    EpochOnly,
    Unmetered,
    Inlined,
    EagerTables,
}

impl EngineVariant {
    fn name(self) -> &'static str {
        match self {
            Self::Metered => "fuel-and-epochs",
            Self::FuelOnly => "fuel-only",
            Self::EpochOnly => "epochs-only",
            Self::Unmetered => "unmetered",
            Self::Inlined => "fuel-and-epochs-inlined",
            Self::EagerTables => "fuel-and-epochs-eager-tables",
        }
    }

    fn fuel(self) -> bool {
        matches!(
            self,
            Self::Metered | Self::FuelOnly | Self::Inlined | Self::EagerTables
        )
    }

    fn epochs(self) -> bool {
        matches!(
            self,
            Self::Metered | Self::EpochOnly | Self::Inlined | Self::EagerTables
        )
    }

    fn engine(self, perf_map: bool) -> Result<Engine, Error> {
        let mut config = Config::new();
        config
            .collector(wasmtime::Collector::DeferredReferenceCounting)
            .consume_fuel(self.fuel())
            .epoch_interruption(self.epochs())
            .table_lazy_init(!matches!(self, Self::EagerTables))
            .compiler_inlining(if matches!(self, Self::Inlined) {
                Inlining::Yes
            } else {
                Inlining::No
            })
            .wasm_exceptions(true);
        if perf_map {
            config.profiler(ProfilingStrategy::PerfMap);
        }
        Engine::new(&config)
    }
}

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
    variant: EngineVariant,
}

impl Guest {
    fn reset_limits(&mut self, fuel: u64) -> Result<(), Error> {
        if self.variant.fuel() {
            self.store.set_fuel(fuel)?;
        }
        if self.variant.epochs() {
            self.store.set_epoch_deadline(6000);
        }
        Ok(())
    }
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
    let mut arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let variants = match arguments.first().and_then(|arg| arg.to_str()) {
        Some("--metering-matrix") => {
            arguments.remove(0);
            vec![
                EngineVariant::Metered,
                EngineVariant::FuelOnly,
                EngineVariant::EpochOnly,
                EngineVariant::Unmetered,
            ]
        }
        Some("--inlining-comparison") => {
            arguments.remove(0);
            vec![EngineVariant::Metered, EngineVariant::Inlined]
        }
        Some("--table-init-comparison") => {
            arguments.remove(0);
            vec![EngineVariant::Metered, EngineVariant::EagerTables]
        }
        _ => vec![EngineVariant::Metered],
    };
    if !(2..=3).contains(&arguments.len()) {
        return Err(Error::msg(
            "usage: convex-wasm-capability-replay [--metering-matrix | --inlining-comparison | --table-init-comparison] TRACE.json BASELINE.wasm [CANDIDATE.wasm]",
        ));
    }
    if variants.len() > 1 && arguments.len() != 2 {
        return Err(Error::msg(
            "Engine comparisons require exactly one Core Wasm module",
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
    let engines: Vec<_> = variants
        .iter()
        .map(|variant| variant.engine(input.perf_map))
        .collect::<Result<_, _>>()?;
    let running = Arc::new(AtomicBool::new(true));
    let ticker = {
        let running = running.clone();
        let engines = engines.clone();
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
                for engine in &engines {
                    engine.increment_epoch();
                }
            }
        })
    };
    let result = run(&engines, &variants, &arguments[1..], &input);
    running.store(false, Ordering::Relaxed);
    ticker
        .join()
        .map_err(|_| Error::msg("Replay epoch ticker panicked"))?;
    result
}

fn run(
    engines: &[Engine],
    variants: &[EngineVariant],
    paths: &[std::ffi::OsString],
    input: &Input,
) -> Result<(), Error> {
    let mut guests = Vec::new();
    for index in 0..paths.len().max(variants.len()) {
        let engine_index = if variants.len() == 1 { 0 } else { index };
        let engine = &engines[engine_index];
        let variant = variants[engine_index];
        let path = &paths[if paths.len() == 1 { 0 } else { index }];
        let module = Module::from_file(engine, path)?;
        let mut linker = Linker::new(engine);
        add_wasi_imports(&mut linker)?;
        add_imports(&mut linker, &module)?;
        linker.define_unknown_imports_as_traps(&module)?;
        let mut store = Store::new(engine, State::new(input.environment.clone()));
        if variant.fuel() {
            store.set_fuel(input.fuel)?;
        }
        if variant.epochs() {
            store.set_epoch_deadline(6000);
        }
        let instance = linker.instantiate(&mut store, &module)?;
        instance
            .get_typed_func::<(), ()>(&mut store, "_initialize")?
            .call(&mut store, ())?;
        let mut guest = Guest {
            store,
            instance,
            variant,
        };
        for case in &input.cases {
            guest.reset_limits(input.fuel)?;
            let Guest {
                store, instance, ..
            } = &mut guest;
            let select =
                instance.get_typed_func::<i64, i32>(&mut *store, "convex_wasm_select_entry")?;
            status(select.call(&mut *store, case.selector as i64)?, "selection")?;
            let prepare = instance
                .get_typed_func::<(), i32>(&mut *store, "convex_wasm_udf_prepare_selected_entry")?;
            status(prepare.call(&mut *store, ())?, "preparation")?;
        }
        guests.push(guest);
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
                // AOT and preparation of another variant can outlast this deadline.
                guests[variant].reset_limits(input.fuel)?;
                let Guest {
                    store,
                    instance,
                    variant: engine_variant,
                } = &mut guests[variant];
                let select =
                    instance.get_typed_func::<i64, i32>(&mut *store, "convex_wasm_select_entry")?;
                let invoke =
                    instance.get_typed_func::<(), i32>(&mut *store, "convex_wasm_udf_run")?;
                status(select.call(&mut *store, case.selector as i64)?, "selection")?;
                store.data_mut().begin(case)?;
                if engine_variant.fuel() {
                    store.set_fuel(input.fuel)?;
                }
                if engine_variant.epochs() {
                    store.set_epoch_deadline(6000);
                }
                let started = Instant::now();
                status(invoke.call(&mut *store, ())?, "handler")?;
                let elapsed = started.elapsed();
                let fuel = if engine_variant.fuel() {
                    Some(
                        input
                            .fuel
                            .checked_sub(store.get_fuel()?)
                            .ok_or_else(|| Error::msg("Replay fuel accounting is inconsistent"))?,
                    )
                } else {
                    None
                };
                let captured_calls = store.data_mut().finish(case)?;
                let state = store.data();
                let guest_and_wasi = elapsed
                    .checked_sub(state.host_time)
                    .ok_or_else(|| Error::msg("Replay timing interval is inconsistent"))?;
                println!(
                    "{}",
                    json!({"variant": variant, "engineVariant": engine_variant.name(), "case": case_index,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use wasm_encoder::{
        CodeSection, ConstExpr, ElementSection, Elements, ExportKind, ExportSection, Function,
        FunctionSection, ImportSection, Instruction, Module as EncodedModule, RefType, TableType,
        TypeSection, ValType,
    };

    fn call_module() -> Vec<u8> {
        let mut module = EncodedModule::new();
        let mut types = TypeSection::new();
        types.ty().function([], [ValType::I32]);
        module.section(&types);
        let mut functions = FunctionSection::new();
        functions.function(0).function(0);
        module.section(&functions);
        let mut exports = ExportSection::new();
        exports.export("sum", ExportKind::Func, 1);
        module.section(&exports);
        let mut code = CodeSection::new();
        let mut leaf = Function::new([]);
        leaf.instruction(&Instruction::I32Const(21))
            .instruction(&Instruction::End);
        code.function(&leaf);
        let mut caller = Function::new([]);
        caller
            .instruction(&Instruction::Call(0))
            .instruction(&Instruction::Call(0))
            .instruction(&Instruction::I32Add)
            .instruction(&Instruction::End);
        code.function(&caller);
        module.section(&code);
        module.finish()
    }

    fn shared_table_module(value: i32) -> Vec<u8> {
        let mut module = EncodedModule::new();
        let mut types = TypeSection::new();
        types.ty().function([], [ValType::I32]);
        types.ty().function([ValType::I32], [ValType::I32]);
        module.section(&types);
        let mut imports = ImportSection::new();
        imports.import(
            "env",
            "table",
            TableType {
                element_type: RefType::FUNCREF,
                minimum: 2,
                maximum: Some(2),
                table64: false,
                shared: false,
            },
        );
        module.section(&imports);
        let mut functions = FunctionSection::new();
        functions.function(0).function(1);
        module.section(&functions);
        let mut exports = ExportSection::new();
        exports.export("call", ExportKind::Func, 1);
        module.section(&exports);
        let mut elements = ElementSection::new();
        elements.active(
            None,
            &ConstExpr::i32_const(0),
            Elements::Functions(Cow::Borrowed(&[0])),
        );
        module.section(&elements);
        let mut code = CodeSection::new();
        let mut leaf = Function::new([]);
        leaf.instruction(&Instruction::I32Const(value))
            .instruction(&Instruction::End);
        code.function(&leaf);
        let mut caller = Function::new([]);
        caller
            .instruction(&Instruction::LocalGet(0))
            .instruction(&Instruction::CallIndirect {
                type_index: 0,
                table_index: 0,
            })
            .instruction(&Instruction::End);
        code.function(&caller);
        module.section(&code);
        module.finish()
    }

    #[test]
    fn table_initialization_preserves_shared_entries_and_traps() -> Result<(), Error> {
        for variant in [EngineVariant::Metered, EngineVariant::EagerTables] {
            let engine = variant.engine(false)?;
            let mut store = Store::new(&engine, ());
            store.set_fuel(1000)?;
            store.set_epoch_deadline(1);
            let table = wasmtime::Table::new(
                &mut store,
                wasmtime::TableType::new(wasmtime::RefType::FUNCREF, 2, Some(2))?,
                wasmtime::Ref::Func(None),
            )?;
            let first_module = Module::new(&engine, shared_table_module(21))?;
            let first = Instance::new(&mut store, &first_module, &[table.into()])?;
            let call = first.get_typed_func::<i32, i32>(&mut store, "call")?;
            assert_eq!(call.call(&mut store, 0)?, 21);
            for (index, trap) in [
                (1, wasmtime::Trap::IndirectCallToNull),
                (2, wasmtime::Trap::TableOutOfBounds),
            ] {
                let error = call.call(&mut store, index).unwrap_err();
                assert_eq!(error.downcast_ref::<wasmtime::Trap>(), Some(&trap));
            }
            // A later module initializes the imported table and changes the
            // earlier instance's dispatch target, including its callee context.
            let second_module = Module::new(&engine, shared_table_module(42))?;
            let _second = Instance::new(&mut store, &second_module, &[table.into()])?;
            assert_eq!(call.call(&mut store, 0)?, 42);
            let wrong_signature = wasmtime::Func::wrap(&mut store, |value: i32| value);
            table.set(&mut store, 0, wasmtime::Ref::Func(Some(wrong_signature)))?;
            let error = call.call(&mut store, 0).unwrap_err();
            assert_eq!(
                error.downcast_ref::<wasmtime::Trap>(),
                Some(&wasmtime::Trap::BadSignature)
            );
        }
        Ok(())
    }

    #[test]
    fn engine_controls_preserve_results_and_fuel_charges() -> Result<(), Error> {
        let wasm = call_module();
        let mut metered_cost = None;
        for variant in [
            EngineVariant::Metered,
            EngineVariant::FuelOnly,
            EngineVariant::EpochOnly,
            EngineVariant::Unmetered,
            EngineVariant::Inlined,
            EngineVariant::EagerTables,
        ] {
            let engine = variant.engine(false)?;
            let module = Module::new(&engine, &wasm)?;
            let mut store = Store::new(&engine, ());
            if variant.fuel() {
                store.set_fuel(100)?;
            }
            if variant.epochs() {
                store.set_epoch_deadline(1);
            }
            let instance = Instance::new(&mut store, &module, &[])?;
            let sum = instance.get_typed_func::<(), i32>(&mut store, "sum")?;
            assert_eq!(sum.call(&mut store, ())?, 42, "{}", variant.name());
            if variant.fuel() {
                let consumed = 100 - store.get_fuel()?;
                assert!(consumed > 0);
                if let Some(expected) = metered_cost {
                    assert_eq!(consumed, expected);
                } else {
                    metered_cost = Some(consumed);
                }
                store.set_fuel(0)?;
                let error = sum.call(&mut store, ()).unwrap_err();
                assert_eq!(
                    error.downcast_ref::<wasmtime::Trap>(),
                    Some(&wasmtime::Trap::OutOfFuel)
                );
            } else {
                assert!(store.get_fuel().is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn epoch_controls_retain_cancellation() -> Result<(), Error> {
        let wasm = call_module();
        for variant in [
            EngineVariant::Metered,
            EngineVariant::EpochOnly,
            EngineVariant::Inlined,
            EngineVariant::EagerTables,
        ] {
            let engine = variant.engine(false)?;
            let module = Module::new(&engine, &wasm)?;
            let mut store = Store::new(&engine, ());
            if variant.fuel() {
                store.set_fuel(100)?;
            }
            store.set_epoch_deadline(1);
            let instance = Instance::new(&mut store, &module, &[])?;
            let sum = instance.get_typed_func::<(), i32>(&mut store, "sum")?;
            engine.increment_epoch();
            let error = sum.call(&mut store, ()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<wasmtime::Trap>(),
                Some(&wasmtime::Trap::Interrupt)
            );
        }
        Ok(())
    }
}
