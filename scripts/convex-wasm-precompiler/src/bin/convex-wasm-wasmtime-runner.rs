use std::error::Error as StdError;
use std::io::{BufRead, Write};

use wasmtime::{Config, Engine, Linker, Module, Store};

#[path = "../wasmtime_wasi.rs"]
mod wasmtime_wasi;
use wasmtime_wasi::{WasiState, add_wasi_imports};

type RunnerResult<T> = Result<T, Box<dyn StdError>>;

fn execute(
    engine: &Engine,
    linker: &Linker<WasiState>,
    module: &Module,
    runner_export: &str,
) -> RunnerResult<(WasiState, i32)> {
    let mut store = Store::new(
        engine,
        WasiState {
            args: vec![b"convex-wasm-static-hermes-runner".to_vec()],
            stderr: Vec::new(),
            stdout: Vec::new(),
        },
    );
    let instance = linker.instantiate(&mut store, module)?;
    instance
        .get_typed_func::<(), ()>(&mut store, "_initialize")?
        .call(&mut store, ())?;
    let status = instance
        .get_typed_func::<(), i32>(&mut store, runner_export)?
        .call(&mut store, ())?;
    Ok((store.into_data(), status))
}

fn main() -> RunnerResult<()> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next().ok_or("missing Wasm module path")?;
    let mut config = Config::new();
    config.wasm_exceptions(true);
    let engine = Engine::new(&config)?;
    let mut linker = Linker::new(&engine);
    add_wasi_imports(&mut linker)?;

    if first == "--serve" {
        let runner_export = arguments
            .next()
            .ok_or("missing runner export name")?
            .into_string()
            .map_err(|_| "runner export name must be valid UTF-8")?;
        let modules: Vec<_> = arguments
            .map(|path| Module::from_file(&engine, path))
            .collect::<Result<_, _>>()?;
        if modules.is_empty() {
            return Err("serve mode requires at least one Wasm module".into());
        }
        let mut output = std::io::stdout().lock();
        writeln!(
            output,
            "{}",
            serde_json::json!({"kind": "ready", "modules": modules.len()})
        )?;
        output.flush()?;
        // Reuse compiled code, but give every request independent guest state.
        // Output is encoded as bytes so arbitrary WASI output remains lossless.
        for line in std::io::stdin().lock().lines() {
            let index: usize = line?.parse()?;
            let module = modules.get(index).ok_or("module index is out of bounds")?;
            let (state, status) = execute(&engine, &linker, module, &runner_export)?;
            writeln!(
                output,
                "{}",
                serde_json::json!({
                    "kind": "result", "module": index, "status": status,
                    "stdout": state.stdout, "stderr": state.stderr,
                })
            )?;
            output.flush()?;
            if status != 0 {
                return Err(format!("{runner_export} returned status {status}").into());
            }
        }
    } else {
        let runner_export = match arguments.next() {
            Some(value) => value
                .into_string()
                .map_err(|_| "runner export name must be valid UTF-8")?,
            None => "convex_wasm_static_hermes_global_probe_run".to_owned(),
        };
        if arguments.next().is_some() {
            return Err("expected a Wasm module path and an optional runner export name".into());
        }
        let module = Module::from_file(&engine, first)?;
        let (state, status) = execute(&engine, &linker, &module, &runner_export)?;
        std::io::stdout().write_all(&state.stdout)?;
        std::io::stderr().write_all(&state.stderr)?;
        if status != 0 {
            return Err(format!("{runner_export} returned status {status}").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{
        CodeSection, ConstExpr, DataSection, EntityType, ExportKind, ExportSection, Function,
        FunctionSection, GlobalSection, GlobalType, ImportSection, Instruction, MemArg,
        MemorySection, MemoryType, TypeSection, ValType,
    };

    fn output_module(engine: &Engine, marker: u8) -> Module {
        let mut wasm = wasm_encoder::Module::new();
        let mut types = TypeSection::new();
        types.ty().function([ValType::I32; 4], [ValType::I32]);
        types.ty().function([], []);
        types.ty().function([], [ValType::I32]);
        wasm.section(&types);
        let mut imports = ImportSection::new();
        imports.import(
            "wasi_snapshot_preview1",
            "fd_write",
            EntityType::Function(0),
        );
        wasm.section(&imports);
        let mut functions = FunctionSection::new();
        functions.function(1).function(2);
        wasm.section(&functions);
        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: Some(1),
            memory64: false,
            shared: false,
            page_size_log2: None,
        });
        wasm.section(&memories);
        let mut globals = GlobalSection::new();
        globals.global(
            GlobalType {
                val_type: ValType::I32,
                mutable: true,
                shared: false,
            },
            &ConstExpr::i32_const(0),
        );
        wasm.section(&globals);
        let mut exports = ExportSection::new();
        exports.export("memory", ExportKind::Memory, 0);
        exports.export("_initialize", ExportKind::Func, 1);
        exports.export("probe", ExportKind::Func, 2);
        wasm.section(&exports);
        let mut code = CodeSection::new();
        let mut init = Function::new([]);
        init.instruction(&Instruction::End);
        code.function(&init);
        let mut run = Function::new([]);
        run.instruction(&Instruction::GlobalGet(0));
        run.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        run.instruction(&Instruction::Unreachable);
        run.instruction(&Instruction::End);
        run.instruction(&Instruction::I32Const(1));
        run.instruction(&Instruction::GlobalSet(0));
        for (address, value) in [(0, 16), (4, 3)] {
            run.instruction(&Instruction::I32Const(address));
            run.instruction(&Instruction::I32Const(value));
            run.instruction(&Instruction::I32Store(MemArg {
                offset: 0,
                align: 2,
                memory_index: 0,
            }));
        }
        for value in [1, 0, 1, 8] {
            run.instruction(&Instruction::I32Const(value));
        }
        run.instruction(&Instruction::Call(0));
        run.instruction(&Instruction::End);
        code.function(&run);
        wasm.section(&code);
        let mut data = DataSection::new();
        data.active(0, &ConstExpr::i32_const(16), [marker, 0, 255]);
        wasm.section(&data);
        Module::new(engine, wasm.finish()).unwrap()
    }

    #[test]
    fn reused_modules_have_fresh_state_and_lossless_output() {
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        add_wasi_imports(&mut linker).unwrap();
        let modules = [output_module(&engine, b'A'), output_module(&engine, b'B')];
        for index in [0, 1, 1, 0] {
            let (state, status) = execute(&engine, &linker, &modules[index], "probe").unwrap();
            assert_eq!(status, 0);
            assert_eq!(state.stdout, [b'A' + index as u8, 0, 255]);
            assert!(state.stderr.is_empty());
        }
    }
}
