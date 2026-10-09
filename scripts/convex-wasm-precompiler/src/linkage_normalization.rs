use std::{error::Error, io};

use wasm_encoder::{
    Encode, ImportSection, Module, TypeSection,
    reencode::{self, Reencode, RoundtripReencoder},
};
use wasmparser::{Dylink0Subsection, FuncType, KnownCustom, Name, Parser, Payload, TypeRef};

#[derive(Default)]
struct CanonicalIndices {
    imported_functions: Vec<u32>,
    function_count: u32,
    types: Vec<u32>,
    ordered_types: Vec<FuncType>,
}

impl Reencode for CanonicalIndices {
    type Error = io::Error;

    fn function_index(&mut self, index: u32) -> Result<u32, reencode::Error<Self::Error>> {
        if index >= self.function_count {
            return Err(reencode::Error::UserError(io::Error::other(
                "linkage metadata refers to an absent function",
            )));
        }
        // Only imports change order. Defined functions retain their indices.
        Ok(self
            .imported_functions
            .get(index as usize)
            .copied()
            .unwrap_or(index))
    }

    fn type_index(&mut self, index: u32) -> Result<u32, reencode::Error<Self::Error>> {
        self.types.get(index as usize).copied().ok_or_else(|| {
            reencode::Error::UserError(io::Error::other(
                "linkage metadata refers to an absent function type",
            ))
        })
    }

    fn parse_type_section(
        &mut self,
        output: &mut TypeSection,
        _section: wasmparser::TypeSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        for ty in &self.ordered_types {
            output.ty().function(
                ty.params()
                    .iter()
                    .copied()
                    .map(|v| RoundtripReencoder.val_type(v).unwrap()),
                ty.results()
                    .iter()
                    .copied()
                    .map(|v| RoundtripReencoder.val_type(v).unwrap()),
            );
        }
        Ok(())
    }

    fn parse_import_section(
        &mut self,
        output: &mut ImportSection,
        section: wasmparser::ImportSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        let all = section.into_imports().collect::<Result<Vec<_>, _>>()?;
        let mut functions: Vec<_> = all
            .iter()
            .filter(|i| matches!(i.ty, TypeRef::Func(_)))
            .copied()
            .collect();
        functions.sort_by_key(|i| (i.module, i.name));
        let mut ordered = functions.into_iter();
        for import in all {
            let import = if matches!(import.ty, TypeRef::Func(_)) {
                ordered
                    .next()
                    .expect("one sorted entry per function import")
            } else {
                import
            };
            reencode::utils::parse_import(self, output, import)?;
        }
        Ok(())
    }
}

/// Normalize final linked modules, before their Core Wasm identity is published.
/// Object relocations and unknown metadata cannot be copied after renumbering.
/// Restrict this operation to the emitter's nonrecursive function signatures and
/// understood metadata; unsupported inputs remain usable by ordinary AOT mode.
pub fn normalize_linkage(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Validate the original too: renumbering must not accidentally repair invalid
    // indices or make originally invalid instructions refer to another type.
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(bytes)?;
    let mut remap = CanonicalIndices::default();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::TypeSection(section) => {
                for group in section.clone() {
                    if group?.types().any(|ty| ty.composite_type.shared) {
                        return Err(
                            "linkage normalization does not support shared function types".into(),
                        );
                    }
                }
                let mut entries = Vec::new();
                for (index, ty) in section.into_iter_err_on_gc_types().enumerate() {
                    let ty = ty?;
                    for value in ty.params().iter().chain(ty.results()) {
                        if matches!(value, wasmparser::ValType::Ref(reference)
                            if !matches!(reference.heap_type(), wasmparser::HeapType::Abstract { .. }))
                        {
                            return Err("linkage normalization does not support concrete reference signatures".into());
                        }
                    }
                    let mut signature = TypeSection::new();
                    signature.ty().function(
                        ty.params()
                            .iter()
                            .copied()
                            .map(|v| RoundtripReencoder.val_type(v).unwrap()),
                        ty.results()
                            .iter()
                            .copied()
                            .map(|v| RoundtripReencoder.val_type(v).unwrap()),
                    );
                    let mut key = Vec::new();
                    signature.encode(&mut key);
                    entries.push((key, index, ty));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                remap.types.resize(entries.len(), 0);
                for (new, (_, old, ty)) in entries.into_iter().enumerate() {
                    remap.types[old] = u32::try_from(new)?;
                    remap.ordered_types.push(ty);
                }
            }
            Payload::ImportSection(section) => {
                let all = section.into_imports().collect::<Result<Vec<_>, _>>()?;
                if all
                    .iter()
                    .any(|import| matches!(import.ty, TypeRef::FuncExact(_)))
                {
                    return Err(
                        "linkage normalization does not support exact function imports".into(),
                    );
                }
                let mut imports = all
                    .into_iter()
                    .filter(|i| matches!(i.ty, TypeRef::Func(_)))
                    .enumerate()
                    .collect::<Vec<_>>();
                remap.imported_functions.resize(imports.len(), 0);
                remap.function_count = u32::try_from(imports.len())?;
                imports.sort_by_key(|(_, i)| (i.module, i.name));
                if imports.windows(2).any(|pair| {
                    (pair[0].1.module, pair[0].1.name) == (pair[1].1.module, pair[1].1.name)
                }) {
                    return Err(
                        "linkage normalization requires unique function import names".into(),
                    );
                }
                for (new, (old, _)) in imports.iter().enumerate() {
                    remap.imported_functions[*old] = u32::try_from(new)?;
                }
            }
            Payload::FunctionSection(section) => {
                remap.function_count = remap
                    .function_count
                    .checked_add(section.count())
                    .ok_or("function count overflow")?;
            }
            Payload::CustomSection(section) => {
                match section.name() {
                    "name" => {
                        let KnownCustom::Name(names) = section.as_known() else {
                            return Err("invalid name section".into());
                        };
                        for name in names {
                            if matches!(name?, Name::Unknown { .. }) {
                                return Err(
                                    "linkage normalization does not support unknown name metadata"
                                        .into(),
                                );
                            }
                        }
                    }
                    "dylink.0" => {
                        let KnownCustom::Dylink0(subsections) = section.as_known() else {
                            return Err("invalid dylink.0 section".into());
                        };
                        for subsection in subsections {
                            if matches!(subsection?, Dylink0Subsection::Unknown { .. }) {
                                return Err("linkage normalization does not support unknown dylink.0 metadata".into());
                            }
                        }
                    }
                    // These sections contain no type or function indices.
                    "producers" | "target_features" => {}
                    name => {
                        return Err(format!(
                            "linkage normalization does not support custom section {name}"
                        )
                        .into());
                    }
                }
            }
            _ => {}
        }
    }
    let mut output = Module::new();
    remap.parse_core_module(&mut output, Parser::new(0), bytes)?;
    let output = output.finish();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(&output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::normalize_linkage;
    use std::borrow::Cow;
    use wasm_encoder::{
        CodeSection, ConstExpr, CustomSection, ElementSection, Elements, EntityType, ExportKind,
        ExportSection, Function, FunctionSection, GlobalType, HeapType, ImportSection, Instruction,
        Module, NameMap, NameSection, RefType, StartSection, TableSection, TableType, TypeSection,
        ValType,
    };
    use wasmtime::{Engine, Global, Linker, Store, Val};

    fn fixture(permuted: bool) -> Vec<u8> {
        let mut module = Module::new();
        let mut types = TypeSection::new();
        let (step_type, result_type, start_type) = if permuted {
            types.ty().function([], []);
            types.ty().function([], [ValType::I32]);
            types.ty().function([ValType::I32], [ValType::I32]);
            (2, 1, 0)
        } else {
            types.ty().function([ValType::I32], [ValType::I32]);
            types.ty().function([], [ValType::I32]);
            types.ty().function([], []);
            (0, 1, 2)
        };
        module.section(&types);
        let mut imports = ImportSection::new();
        let (first, second, step, seed) = if permuted {
            (("a", "seed", result_type), ("z", "step", step_type), 1, 0)
        } else {
            (("z", "step", step_type), ("a", "seed", result_type), 0, 1)
        };
        imports.import(first.0, first.1, EntityType::Function(first.2));
        imports.import(
            "env",
            "state",
            EntityType::Global(GlobalType {
                val_type: ValType::I32,
                mutable: true,
                shared: false,
            }),
        );
        imports.import(second.0, second.1, EntityType::Function(second.2));
        module.section(&imports);
        let mut functions = FunctionSection::new();
        functions
            .function(result_type)
            .function(step_type)
            .function(start_type)
            .function(result_type);
        module.section(&functions);
        let mut tables = TableSection::new();
        tables.table(TableType {
            element_type: RefType::FUNCREF,
            minimum: 2,
            maximum: Some(2),
            table64: false,
            shared: false,
        });
        module.section(&tables);
        let mut exports = ExportSection::new();
        exports
            .export("run", ExportKind::Func, 2)
            .export("step", ExportKind::Func, step)
            .export("indirect", ExportKind::Func, 3)
            .export("reference_is_null", ExportKind::Func, 5);
        module.section(&exports);
        module.section(&StartSection { function_index: 4 });
        let mut elements = ElementSection::new();
        elements.active(
            Some(0),
            &ConstExpr::i32_const(0),
            Elements::Functions(Cow::Borrowed(&[step, 2])),
        );
        module.section(&elements);
        let mut code = CodeSection::new();
        let mut run = Function::new([]);
        run.instruction(&Instruction::Call(seed))
            .instruction(&Instruction::Call(step))
            .instruction(&Instruction::End);
        code.function(&run);
        let mut indirect = Function::new([]);
        indirect
            .instruction(&Instruction::LocalGet(0))
            .instruction(&Instruction::I32Const(0))
            .instruction(&Instruction::CallIndirect {
                type_index: step_type,
                table_index: 0,
            })
            .instruction(&Instruction::End);
        code.function(&indirect);
        let mut start = Function::new([]);
        start
            .instruction(&Instruction::Call(2))
            .instruction(&Instruction::GlobalSet(0))
            .instruction(&Instruction::End);
        code.function(&start);
        let mut reference = Function::new([]);
        reference
            .instruction(&Instruction::RefFunc(step))
            .instruction(&Instruction::RefIsNull)
            .instruction(&Instruction::End);
        code.function(&reference);
        module.section(&code);
        let mut names = NameSection::new();
        let mut functions = NameMap::new();
        functions.append(0, first.1);
        functions.append(1, second.1);
        functions.append(2, "run");
        names.functions(&functions);
        module.section(&names);
        // Dynamic-linking memory/table requirements are not function indices.
        module.section(&CustomSection {
            name: "dylink.0".into(),
            data: Cow::Borrowed(&[1, 4, 0, 0, 2, 0]),
        });
        module.finish()
    }

    fn execute(bytes: &[u8]) {
        let engine = Engine::default();
        let mut store = Store::new(&engine, ());
        let state = Global::new(
            &mut store,
            wasmtime::GlobalType::new(wasmtime::ValType::I32, wasmtime::Mutability::Var),
            Val::I32(0),
        )
        .unwrap();
        let mut linker = Linker::new(&engine);
        linker.define(&mut store, "env", "state", state).unwrap();
        linker.func_wrap("a", "seed", || 40i32).unwrap();
        linker
            .func_wrap("z", "step", |value: i32| value + 2)
            .unwrap();
        let module = wasmtime::Module::new(&engine, bytes).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        assert_eq!(state.get(&mut store).i32(), Some(42));
        assert_eq!(
            instance
                .get_typed_func::<(), i32>(&mut store, "run")
                .unwrap()
                .call(&mut store, ())
                .unwrap(),
            42
        );
        for name in ["step", "indirect"] {
            assert_eq!(
                instance
                    .get_typed_func::<i32, i32>(&mut store, name)
                    .unwrap()
                    .call(&mut store, 10)
                    .unwrap(),
                12
            );
        }
        assert_eq!(
            instance
                .get_typed_func::<(), i32>(&mut store, "reference_is_null")
                .unwrap()
                .call(&mut store, ())
                .unwrap(),
            0
        );
    }

    #[test]
    fn remaps_imports_types_calls_exports_elements_start_and_ref_func() {
        for permuted in [false, true] {
            let input = fixture(permuted);
            let normalized = normalize_linkage(&input).unwrap();
            execute(&input);
            execute(&normalized);
            assert_eq!(normalize_linkage(&normalized).unwrap(), normalized);
            let mut seen_names = false;
            for payload in wasmparser::Parser::new(0).parse_all(&normalized) {
                if let wasmparser::Payload::CustomSection(section) = payload.unwrap() {
                    if let wasmparser::KnownCustom::Name(names) = section.as_known() {
                        for name in names {
                            if let wasmparser::Name::Function(entries) = name.unwrap() {
                                for entry in entries {
                                    let entry = entry.unwrap();
                                    if entry.name == "step" {
                                        assert_eq!(entry.index, 1);
                                        seen_names = true;
                                    }
                                }
                            }
                        }
                    }
                    if section.name() == "dylink.0" {
                        assert_eq!(section.data(), &[1, 4, 0, 0, 2, 0]);
                    }
                }
            }
            assert!(seen_names);
        }
    }

    #[test]
    fn rejects_metadata_that_cannot_be_remapped() {
        for (name, data) in [
            ("reloc.CODE", &[][..]),
            ("name", &[127, 0]),
            ("dylink.0", &[127, 0]),
        ] {
            let mut module = Module::new();
            module.section(&CustomSection {
                name: name.into(),
                data: data.into(),
            });
            assert!(
                normalize_linkage(&module.finish())
                    .unwrap_err()
                    .to_string()
                    .contains("does not support")
            );
        }
        let mut module = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([], []);
        module.section(&types);
        let mut names = NameSection::new();
        let mut type_names = NameMap::new();
        type_names.append(999, "absent");
        names.types(&type_names);
        module.section(&names);
        assert!(
            normalize_linkage(&module.finish())
                .unwrap_err()
                .to_string()
                .contains("absent function type")
        );
    }

    #[test]
    fn rejects_duplicate_imports_and_concrete_reference_signatures() {
        let mut module = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([], []);
        module.section(&types);
        let mut imports = ImportSection::new();
        imports.import("env", "duplicate", EntityType::Function(0));
        imports.import("env", "duplicate", EntityType::Function(0));
        module.section(&imports);
        assert!(
            normalize_linkage(&module.finish())
                .unwrap_err()
                .to_string()
                .contains("unique function import names")
        );
        let mut module = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([], []);
        types.ty().function(
            [ValType::Ref(RefType {
                nullable: true,
                heap_type: HeapType::Concrete(0),
            })],
            [],
        );
        module.section(&types);
        assert!(
            normalize_linkage(&module.finish())
                .unwrap_err()
                .to_string()
                .contains("concrete reference signatures")
        );
    }

    #[test]
    fn accepts_abstract_exception_and_function_reference_signatures() {
        let mut module = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([ValType::Ref(RefType::EXNREF)], []);
        types.ty().function([ValType::Ref(RefType::FUNCREF)], []);
        module.section(&types);
        let normalized = normalize_linkage(&module.finish()).unwrap();
        assert_eq!(normalize_linkage(&normalized).unwrap(), normalized);
    }
}
