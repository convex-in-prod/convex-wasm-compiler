use std::error::Error as StdError;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use wasmtime::{Caller, Config, Engine, Error, Extern, Linker, Memory, Module, Store};

type RunnerResult<T> = Result<T, Box<dyn StdError>>;

struct State {
    args: Vec<Vec<u8>>,
    stderr: Vec<u8>,
    stdout: Vec<u8>,
}

fn memory(caller: &mut Caller<'_, State>) -> Result<Memory, Error> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| Error::msg("guest did not export memory"))
}

fn checked_offset(value: i32) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::msg("negative guest memory offset"))
}

fn write_u32(caller: &mut Caller<'_, State>, offset: i32, value: u32) -> Result<(), Error> {
    memory(caller)?
        .write(caller, checked_offset(offset)?, &value.to_le_bytes())
        .map_err(Error::from)
}

fn write_u64(caller: &mut Caller<'_, State>, offset: i32, value: u64) -> Result<(), Error> {
    memory(caller)?
        .write(caller, checked_offset(offset)?, &value.to_le_bytes())
        .map_err(Error::from)
}

fn read_u32(caller: &mut Caller<'_, State>, offset: usize) -> Result<u32, Error> {
    let mut bytes = [0_u8; 4];
    memory(caller)?
        .read(caller, offset, &mut bytes)
        .map_err(Error::from)?;
    Ok(u32::from_le_bytes(bytes))
}

fn add_wasi_imports(linker: &mut Linker<State>) -> Result<(), Error> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_sizes_get",
        |mut caller: Caller<'_, State>, argc_ptr: i32, size_ptr: i32| {
            let argc = u32::try_from(caller.data().args.len())
                .map_err(|_| Error::msg("too many guest arguments"))?;
            let byte_count = caller.data().args.iter().try_fold(0_u32, |total, arg| {
                let len = u32::try_from(arg.len() + 1)
                    .map_err(|_| Error::msg("guest argument too long"))?;
                total
                    .checked_add(len)
                    .ok_or_else(|| Error::msg("guest arguments exceed u32"))
            })?;
            write_u32(&mut caller, argc_ptr, argc)?;
            write_u32(&mut caller, size_ptr, byte_count)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_get",
        |mut caller: Caller<'_, State>, argv_ptr: i32, argv_buf_ptr: i32| {
            let args = caller.data().args.clone();
            let argv_base = checked_offset(argv_ptr)?;
            let mut buffer_offset = checked_offset(argv_buf_ptr)?;
            let guest_memory = memory(&mut caller)?;
            for (index, arg) in args.iter().enumerate() {
                let guest_pointer = u32::try_from(buffer_offset)
                    .map_err(|_| Error::msg("guest argument pointer exceeds u32"))?;
                guest_memory
                    .write(
                        &mut caller,
                        argv_base + index * 4,
                        &guest_pointer.to_le_bytes(),
                    )
                    .map_err(Error::from)?;
                guest_memory
                    .write(&mut caller, buffer_offset, arg)
                    .map_err(Error::from)?;
                buffer_offset += arg.len();
                guest_memory
                    .write(&mut caller, buffer_offset, &[0])
                    .map_err(Error::from)?;
                buffer_offset += 1;
            }
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_sizes_get",
        |mut caller: Caller<'_, State>, count_ptr: i32, size_ptr: i32| {
            write_u32(&mut caller, count_ptr, 0)?;
            write_u32(&mut caller, size_ptr, 0)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_get",
        |_caller: Caller<'_, State>, _environ_ptr: i32, _buffer_ptr: i32| 0_i32,
    )?;
    linker.func_wrap(
        "env",
        "emscripten_notify_memory_growth",
        |_caller: Caller<'_, State>, _memory_index: i32| {},
    )?;
    linker.func_wrap(
        "env",
        "__syscall_unlinkat",
        |_caller: Caller<'_, State>, _directory_fd: i32, _path_ptr: i32, _flags: i32| -2_i32,
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_close",
        |_caller: Caller<'_, State>, fd: i32| if (0..=2).contains(&fd) { 0_i32 } else { 8_i32 },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_fdstat_get",
        |mut caller: Caller<'_, State>, fd: i32, stat_ptr: i32| {
            if !(0..=2).contains(&fd) {
                return Ok::<i32, Error>(8);
            }
            let mut stat = [0_u8; 24];
            stat[0] = 2;
            memory(&mut caller)?
                .write(&mut caller, checked_offset(stat_ptr)?, &stat)
                .map_err(Error::from)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_seek",
        |mut caller: Caller<'_, State>, _fd: i32, _offset: i64, _whence: i32, result_ptr: i32| {
            write_u64(&mut caller, result_ptr, 0)?;
            Ok::<i32, Error>(8)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_read",
        |mut caller: Caller<'_, State>, _fd: i32, _iov_ptr: i32, _iov_count: i32, read_ptr: i32| {
            write_u32(&mut caller, read_ptr, 0)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_pread",
        |mut caller: Caller<'_, State>,
         _fd: i32,
         _iov_ptr: i32,
         _iov_count: i32,
         _offset: i64,
         read_ptr: i32| {
            write_u32(&mut caller, read_ptr, 0)?;
            Ok::<i32, Error>(8)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_write",
        |mut caller: Caller<'_, State>, fd: i32, iov_ptr: i32, iov_count: i32, written_ptr: i32| {
            let count = usize::try_from(iov_count)
                .map_err(|_| Error::msg("negative fd_write iovec count"))?;
            let iov_base = checked_offset(iov_ptr)?;
            let guest_memory = memory(&mut caller)?;
            let mut bytes = Vec::new();
            for index in 0..count {
                let entry = iov_base + index * 8;
                let data_ptr = usize::try_from(read_u32(&mut caller, entry)?)
                    .map_err(|_| Error::msg("iovec pointer exceeds usize"))?;
                let data_len = usize::try_from(read_u32(&mut caller, entry + 4)?)
                    .map_err(|_| Error::msg("iovec length exceeds usize"))?;
                let start = bytes.len();
                bytes.resize(start + data_len, 0);
                guest_memory
                    .read(&caller, data_ptr, &mut bytes[start..])
                    .map_err(Error::from)?;
            }
            match fd {
                1 => caller.data_mut().stdout.extend_from_slice(&bytes),
                2 => caller.data_mut().stderr.extend_from_slice(&bytes),
                _ => return Ok::<i32, Error>(8),
            }
            let written = u32::try_from(bytes.len())
                .map_err(|_| Error::msg("fd_write byte count exceeds u32"))?;
            write_u32(&mut caller, written_ptr, written)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "clock_time_get",
        |mut caller: Caller<'_, State>, _clock_id: i32, _precision: i64, result_ptr: i32| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::msg("system time predates Unix epoch"))?
                .as_nanos();
            write_u64(
                &mut caller,
                result_ptr,
                u64::try_from(nanos).map_err(|_| Error::msg("system time exceeds u64"))?,
            )?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "random_get",
        |mut caller: Caller<'_, State>, buffer_ptr: i32, buffer_len: i32| {
            let len = usize::try_from(buffer_len)
                .map_err(|_| Error::msg("negative random_get length"))?;
            memory(&mut caller)?
                .write(&mut caller, checked_offset(buffer_ptr)?, &vec![0x5a; len])
                .map_err(Error::from)?;
            Ok::<i32, Error>(0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "proc_exit",
        |_caller: Caller<'_, State>, status: i32| -> Result<(), Error> {
            Err(Error::msg(format!("guest exited with status {status}")))
        },
    )?;
    Ok(())
}

fn main() -> RunnerResult<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let module_path = arguments.next().ok_or("missing Wasm module path")?;
    let runner_export = match arguments.next() {
        Some(value) => value
            .into_string()
            .map_err(|_| "runner export name must be valid UTF-8")?,
        None => "convex_wasm_static_hermes_global_probe_run".to_owned(),
    };
    if arguments.next().is_some() {
        return Err("expected a Wasm module path and an optional runner export name".into());
    }
    let mut config = Config::new();
    config.wasm_exceptions(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_file(&engine, module_path)?;
    let mut linker = Linker::new(&engine);
    add_wasi_imports(&mut linker)?;
    let mut store = Store::new(
        &engine,
        State {
            args: vec![b"convex-wasm-static-hermes-runner".to_vec()],
            stderr: Vec::new(),
            stdout: Vec::new(),
        },
    );
    let instance = linker.instantiate(&mut store, &module)?;
    instance
        .get_typed_func::<(), ()>(&mut store, "_initialize")?
        .call(&mut store, ())?;
    let status = instance
        .get_typed_func::<(), i32>(&mut store, &runner_export)?
        .call(&mut store, ())?;
    std::io::stdout().write_all(&store.data().stdout)?;
    std::io::stderr().write_all(&store.data().stderr)?;
    if status != 0 {
        return Err(format!("{runner_export} returned status {status}").into());
    }
    Ok(())
}
