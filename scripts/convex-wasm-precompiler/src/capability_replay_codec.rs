//! Typed capability transport for offline replay, using captured Convex JSON.
//! Ordinary JSON numbers must remain doubles in packed documents: FlexBuffers
//! integer tags are decoded as BigInt by the guest runtime.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{
    Serialize, Serializer,
    ser::{Error, SerializeMap, SerializeSeq},
};
use serde_json::{Map, Value, json};

type CodecResult<T> = Result<T, &'static str>;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_ARRAY: usize = 8192;
const MAX_FIELDS: usize = 1024;

enum Special {
    Integer(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Undefined,
}

fn special(value: &Value) -> CodecResult<Option<Special>> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    if !object.keys().any(|key| key.starts_with('$')) {
        return Ok(None);
    }
    if object.len() != 1 {
        return Err("Malformed tagged replay value");
    }
    let (key, value) = object.iter().next().unwrap();
    if key == "$undefined" && value.is_null() {
        return Ok(Some(Special::Undefined));
    }
    if !matches!(key.as_str(), "$integer" | "$float" | "$bytes") {
        return Err("Unsupported tagged replay value");
    }
    let bytes = STANDARD
        .decode(value.as_str().ok_or("Invalid replay tag payload")?)
        .map_err(|_| "Invalid replay base64")?;
    Ok(Some(match key.as_str() {
        "$bytes" => Special::Bytes(bytes),
        "$integer" => Special::Integer(i64::from_le_bytes(
            bytes.try_into().map_err(|_| "Invalid integer payload")?,
        )),
        "$float" => Special::Float(f64::from_le_bytes(
            bytes.try_into().map_err(|_| "Invalid float payload")?,
        )),
        _ => unreachable!(),
    }))
}

fn number(value: f64) -> Value {
    if !value.is_finite() || (value == 0.0 && value.is_sign_negative()) {
        json!({"$float": STANDARD.encode(value.to_le_bytes())})
    } else if value.fract() == 0.0 && value.abs() <= 9007199254740991.0 {
        // JSON capture has one Number type; avoid an artificial 1 versus 1.0
        // mismatch when comparing decoded guest requests with that capture.
        Value::from(value as i64)
    } else {
        Value::from(value)
    }
}

struct Writer(Vec<u8>);
impl Writer {
    fn append(&mut self, bytes: &[u8]) -> CodecResult<()> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err("Replay frame exceeds byte limit");
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, value: u8) -> CodecResult<()> {
        self.append(&[value])
    }
    fn count(&mut self, value: usize) -> CodecResult<()> {
        self.append(
            &u32::try_from(value)
                .map_err(|_| "Replay length exceeds u32")?
                .to_le_bytes(),
        )
    }
    fn slice(&mut self, value: &[u8]) -> CodecResult<()> {
        self.count(value.len())?;
        self.append(value)
    }
    fn value(
        &mut self,
        value: &Value,
        depth: usize,
        patch: bool,
        deleted: bool,
    ) -> CodecResult<()> {
        if let Some(tag) = special(value)? {
            return match tag {
                Special::Integer(value) => {
                    self.byte(4)?;
                    self.append(&value.to_le_bytes())
                }
                Special::Float(value) => {
                    self.byte(3)?;
                    self.append(&value.to_le_bytes())
                }
                Special::Bytes(value) => {
                    self.byte(6)?;
                    self.slice(&value)
                }
                Special::Undefined if deleted => self.byte(12),
                Special::Undefined => Err("Undefined replay value outside a patch field"),
            };
        }
        match value {
            Value::Null => self.byte(0),
            Value::Bool(value) => self.byte(if *value { 2 } else { 1 }),
            Value::Number(value) => {
                self.byte(3)?;
                self.append(&value.as_f64().ok_or("Invalid replay number")?.to_le_bytes())
            }
            Value::String(value) => {
                self.byte(5)?;
                self.slice(value.as_bytes())
            }
            Value::Array(values) => {
                if depth >= MAX_DEPTH || values.len() > MAX_ARRAY {
                    return Err("Replay array exceeds limits");
                }
                self.byte(7)?;
                self.count(values.len())?;
                for value in values {
                    self.value(value, depth + 1, false, false)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                if depth >= MAX_DEPTH || values.len() > MAX_FIELDS {
                    return Err("Replay object exceeds limits");
                }
                self.byte(8)?;
                self.count(values.len())?;
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                for (key, value) in entries {
                    self.slice(key.as_bytes())?;
                    self.value(value, depth + 1, false, patch && depth == 0)?;
                }
                Ok(())
            }
        }
    }
}

pub fn encode_value(value: &Value, patch: bool) -> CodecResult<Vec<u8>> {
    let mut writer = Writer(b"CVA1".to_vec());
    writer.value(value, 0, patch, false)?;
    Ok(writer.0)
}

// Use the standard FlexBuffers serializer, but override Number and Convex tags.
// Prevalidation through CVA1 bounds recursion and rejects unsupported values.
struct Packed<'a>(&'a Value);
impl Serialize for Packed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(tag) = special(self.0).map_err(S::Error::custom)? {
            return match tag {
                Special::Integer(value) => serializer.serialize_i64(value),
                Special::Float(value) => serializer.serialize_f64(value),
                Special::Bytes(value) => serializer.serialize_bytes(&value),
                Special::Undefined => Err(S::Error::custom("Undefined packed value")),
            };
        }
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => serializer.serialize_f64(
                value
                    .as_f64()
                    .ok_or_else(|| S::Error::custom("Invalid number"))?,
            ),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Packed(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    if key.contains('\0') {
                        return Err(S::Error::custom("Packed key contains NUL"));
                    }
                    map.serialize_entry(key, &Packed(value))?;
                }
                map.end()
            }
        }
    }
}

fn packed_document(writer: &mut Writer, document: &Value) -> CodecResult<()> {
    if !document.is_object() || special(document)?.is_some() {
        return Err("Replay document is not an object");
    }
    encode_value(document, false)?;
    let bytes =
        flexbuffers::to_vec(Packed(document)).map_err(|_| "Invalid packed replay document")?;
    writer.byte(10)?;
    writer.slice(&bytes)
}

pub fn encode_document(document: &Value) -> CodecResult<Vec<u8>> {
    if document.is_null() {
        return encode_value(document, false);
    }
    let mut writer = Writer(b"CVA1".to_vec());
    packed_document(&mut writer, document)?;
    Ok(writer.0)
}

pub fn encode_documents(documents: &[Value]) -> CodecResult<Vec<u8>> {
    if documents.len() > MAX_ARRAY {
        return Err("Replay collection exceeds limit");
    }
    let mut writer = Writer(b"CVA1".to_vec());
    writer.byte(11)?;
    writer.count(documents.len())?;
    for document in documents {
        packed_document(&mut writer, document)?;
    }
    Ok(writer.0)
}

pub fn encode_stream_result(result: &Value) -> CodecResult<Vec<u8>> {
    let object = result.as_object().ok_or("Invalid replay stream result")?;
    if object.len() != 2 {
        return Err("Invalid replay stream result");
    }
    let done = object
        .get("done")
        .and_then(Value::as_bool)
        .ok_or("Invalid replay stream done flag")?;
    let document = object.get("value").ok_or("Missing replay stream value")?;
    if done && !document.is_null() {
        return Err("Finished replay stream has a document");
    }
    let mut writer = Writer(b"CVA1".to_vec());
    writer.byte(8)?;
    writer.count(2)?;
    writer.slice(b"done")?;
    writer.byte(if done { 2 } else { 1 })?;
    writer.slice(b"value")?;
    if done {
        writer.byte(0)?;
    } else {
        packed_document(&mut writer, document)?;
    }
    Ok(writer.0)
}

struct Reader<'a> {
    remaining: &'a [u8],
    nodes: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> CodecResult<Self> {
        if bytes.len() > MAX_BYTES {
            return Err("Replay frame exceeds byte limit");
        }
        Ok(Self {
            remaining: bytes
                .strip_prefix(magic)
                .ok_or("Invalid replay frame header")?,
            nodes: 0,
        })
    }
    fn take(&mut self, length: usize) -> CodecResult<&'a [u8]> {
        if length > self.remaining.len() {
            return Err("Truncated replay frame");
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }
    fn byte(&mut self) -> CodecResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> CodecResult<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn u64(&mut self) -> CodecResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn slice(&mut self) -> CodecResult<&'a [u8]> {
        let length = self.u32()?;
        self.take(length)
    }
    fn string(&mut self) -> CodecResult<String> {
        String::from_utf8(self.slice()?.to_vec()).map_err(|_| "Invalid replay UTF-8")
    }
    fn finish(&self) -> CodecResult<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err("Trailing replay frame bytes")
        }
    }
    fn count(&mut self, maximum: usize) -> CodecResult<usize> {
        let count = self.u32()?;
        if count > maximum || count > self.remaining.len() {
            return Err("Replay count exceeds limit");
        }
        Ok(count)
    }
    fn value(&mut self, depth: usize, patch: bool, deleted: bool) -> CodecResult<Value> {
        Ok(match self.byte()? {
            0 => Value::Null,
            1 => Value::Bool(false),
            2 => Value::Bool(true),
            3 => number(f64::from_bits(self.u64()?)),
            4 => json!({"$integer": STANDARD.encode(self.take(8)?)}),
            5 => Value::String(self.string()?),
            6 => json!({"$bytes": STANDARD.encode(self.slice()?)}),
            7 => {
                if depth >= MAX_DEPTH {
                    return Err("Replay nesting exceeds limit");
                }
                let count = self.count(MAX_ARRAY)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.value(depth + 1, false, false)?);
                }
                Value::Array(values)
            }
            8 => {
                if depth >= MAX_DEPTH {
                    return Err("Replay nesting exceeds limit");
                }
                let count = self.count(MAX_FIELDS)?;
                let mut values = Map::new();
                let mut previous: Option<String> = None;
                for _ in 0..count {
                    let key = self.string()?;
                    if key.starts_with('$')
                        || previous
                            .as_ref()
                            .is_some_and(|prev| prev.encode_utf16().cmp(key.encode_utf16()).is_ge())
                    {
                        return Err("Invalid or unordered replay field");
                    }
                    previous = Some(key.clone());
                    values.insert(key, self.value(depth + 1, false, patch && depth == 0)?);
                }
                Value::Object(values)
            }
            12 if deleted => json!({"$undefined": null}),
            // Packed documents are host-to-guest only; pending timestamps need
            // a separately captured transaction contract, not a guessed value.
            _ => return Err("Unsupported guest replay value tag"),
        })
    }
    fn optional_value(&mut self) -> CodecResult<Value> {
        match self.byte()? {
            0 => Ok(json!({"$undefined": null})),
            1 => decode_value(self.slice()?, false),
            _ => Err("Invalid query optional value tag"),
        }
    }
    fn integer(&mut self) -> CodecResult<Value> {
        let value = self.u64()?;
        if value > 9007199254740991 {
            return Err("Query integer exceeds safe range");
        }
        Ok(Value::from(value))
    }
    fn expression(&mut self, depth: usize) -> CodecResult<Value> {
        self.nodes += 1;
        if depth >= MAX_DEPTH || self.nodes > 4096 {
            return Err("Query expression exceeds limits");
        }
        let tag = self.byte()?;
        let (name, value) = match tag {
            1 => ("$literal", self.optional_value()?),
            2 => ("$field", Value::String(self.string()?)),
            3..=13 => {
                let names = [
                    "$eq", "$neq", "$lt", "$lte", "$gt", "$gte", "$add", "$sub", "$mul", "$div",
                    "$mod",
                ];
                (
                    names[usize::from(tag - 3)],
                    Value::Array(vec![
                        self.expression(depth + 1)?,
                        self.expression(depth + 1)?,
                    ]),
                )
            }
            14 | 15 => (
                if tag == 14 { "$neg" } else { "$not" },
                self.expression(depth + 1)?,
            ),
            16 | 17 => {
                let count = self.count(256)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.expression(depth + 1)?);
                }
                (if tag == 16 { "$and" } else { "$or" }, Value::Array(values))
            }
            _ => return Err("Invalid query expression tag"),
        };
        Ok(json!({name: value}))
    }
}

pub fn decode_value(bytes: &[u8], patch: bool) -> CodecResult<Value> {
    let mut reader = Reader::new(bytes, b"CVA1")?;
    let value = reader.value(0, patch, false)?;
    reader.finish()?;
    Ok(value)
}

#[derive(Debug, PartialEq)]
pub enum QueryTerminal {
    Collect,
    First,
    Unique,
    Stream,
}

pub fn decode_query(bytes: &[u8]) -> CodecResult<(QueryTerminal, Value)> {
    let mut reader = Reader::new(bytes, b"CQR1")?;
    let terminal = match reader.byte()? {
        1 => QueryTerminal::Collect,
        2 => QueryTerminal::First,
        3 => QueryTerminal::Unique,
        4 => QueryTerminal::Stream,
        _ => return Err("Unsupported replay query terminal"),
    };
    let kind = reader.byte()?;
    let order = match reader.byte()? {
        0 => Value::Null,
        1 => Value::from("asc"),
        2 => Value::from("desc"),
        _ => return Err("Invalid query order"),
    };
    let table = reader.string()?;
    let source = match kind {
        1 => json!({"type": "FullTableScan", "tableName": table, "order": order}),
        2 | 3 => {
            let index = reader.string()?;
            let count = reader.count(256)?;
            let mut constraints = Vec::with_capacity(count);
            for i in 0..count {
                let tag = reader.byte()?;
                let field = reader.string()?;
                let (name, value) = match (kind, tag) {
                    (2, 1..=5) => (
                        ["Eq", "Gt", "Gte", "Lt", "Lte"][usize::from(tag - 1)],
                        reader.optional_value()?,
                    ),
                    (3, 1) if i == 0 => ("Search", Value::from(reader.string()?)),
                    (3, 2) if i > 0 => ("Eq", reader.optional_value()?),
                    _ => return Err("Invalid query constraint"),
                };
                constraints.push(json!({"type": name, "fieldPath": field, "value": value}));
            }
            if kind == 2 {
                json!({"type": "IndexRange", "indexName": format!("{table}.{index}"), "range": constraints, "order": order})
            } else {
                if !order.is_null() || count == 0 {
                    return Err("Invalid search query");
                }
                json!({"type": "Search", "indexName": format!("{table}.{index}"), "filters": constraints})
            }
        }
        _ => return Err("Invalid query source"),
    };
    let count = reader.count(256)?;
    let mut operators = Vec::with_capacity(count);
    for _ in 0..count {
        operators.push(match reader.byte()? {
            1 => json!({"filter": reader.expression(0)?}),
            2 => json!({"limit": reader.integer()?}),
            _ => return Err("Invalid query operator"),
        });
    }
    reader.finish()?;
    Ok((terminal, json!({"source": source, "operators": operators})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_json_numbers_preserve_f64_bits() {
        for decimal in [
            "100.10010010010011",
            "0.84551240822557006",
            "-0.0",
            "1e-320",
            "9007199254740991",
        ] {
            let expected = decimal.parse::<f64>().unwrap();
            let captured: Value = serde_json::from_str(decimal).unwrap();
            assert_eq!(captured.as_f64().unwrap().to_bits(), expected.to_bits());
            let frame = encode_value(&captured, false).unwrap();
            // The transport stores Number as its exact little-endian f64.
            assert_eq!(&frame[5..13], &expected.to_le_bytes());
        }
    }

    #[test]
    fn values_preserve_convex_types_and_patch_deletions() {
        let value = json!({"a": [null, true, false, 1, 1.25, "text"],
            "bytes": {"$bytes": "AAEC"}, "integer": {"$integer": "//////////8="},
            "negativeZero": {"$float": "AAAAAAAAAIA="}});
        assert_eq!(
            decode_value(&encode_value(&value, false).unwrap(), false).unwrap(),
            value
        );
        let patch = json!({"removed": {"$undefined": null}});
        let bytes = encode_value(&patch, true).unwrap();
        assert_eq!(decode_value(&bytes, true).unwrap(), patch);
        assert!(decode_value(&bytes, false).is_err());
        assert!(encode_value(&json!({"nested": patch}), true).is_err());
    }

    #[test]
    fn packed_documents_keep_numbers_distinct_from_bigints() {
        let frame = encode_document(
            &json!({"number": 7, "integer": {"$integer": "BwAAAAAAAAA="}, "nested": [7, 1.25]}),
        )
        .unwrap();
        assert_eq!(&frame[..5], b"CVA1\x0a");
        let reader = flexbuffers::Reader::get_root(&frame[9..]).unwrap();
        let map = reader.get_map().unwrap();
        assert_eq!(
            map.idx("number").flexbuffer_type(),
            flexbuffers::FlexBufferType::Float
        );
        assert_eq!(
            map.idx("integer").flexbuffer_type(),
            flexbuffers::FlexBufferType::Int
        );
        assert_eq!(map.idx("nested").get_vector().unwrap().idx(0).as_f64(), 7.0);
        assert!(encode_document(&json!({"nul\0key": 1})).is_err());
        let collection = encode_documents(&[json!({"n": 1}), json!({"n": 2})]).unwrap();
        assert_eq!(&collection[..9], b"CVA1\x0b\x02\0\0\0");
        assert_eq!(collection[9], 10);
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_invalid_fields() {
        let bytes = encode_value(&json!({"a": [1, "x"]}), false).unwrap();
        for length in 0..bytes.len() {
            assert!(decode_value(&bytes[..length], false).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_value(&trailing, false).is_err());
        assert!(decode_value(b"CVA1\x08\x02\0\0\0\x01\0\0\0b\0\x01\0\0\0a\0", false).is_err());
        assert!(encode_value(&json!({"$unknown": null}), false).is_err());
        assert!(encode_value(&json!({"$integer": "AA=="}), false).is_err());
        assert!(decode_value(b"CVA1\x09", false).is_err());
    }

    #[test]
    fn decodes_index_query_with_undefined_filter_and_limit() {
        let mut writer = Writer(b"CQR1\x01\x02\x01".to_vec());
        writer.slice(b"records").unwrap();
        writer.slice(b"by_owner").unwrap();
        writer.count(1).unwrap();
        writer.byte(1).unwrap();
        writer.slice(b"owner").unwrap();
        writer.byte(1).unwrap();
        writer
            .slice(&encode_value(&json!("a"), false).unwrap())
            .unwrap();
        writer.count(2).unwrap();
        writer.byte(1).unwrap();
        writer.byte(3).unwrap();
        writer.byte(2).unwrap();
        writer.slice(b"optional").unwrap();
        writer.byte(1).unwrap();
        writer.byte(0).unwrap();
        writer.byte(2).unwrap();
        writer.append(&1u64.to_le_bytes()).unwrap();
        let expected = json!({"source": {"type": "IndexRange", "indexName": "records.by_owner", "order": "asc",
            "range": [{"type": "Eq", "fieldPath": "owner", "value": "a"}]},
            "operators": [{"filter": {"$eq": [{"$field": "optional"}, {"$literal": {"$undefined": null}}]}}, {"limit": 1}]});
        assert_eq!(
            decode_query(&writer.0).unwrap(),
            (QueryTerminal::Collect, expected)
        );
        for length in 0..writer.0.len() {
            assert!(decode_query(&writer.0[..length]).is_err());
        }
    }
}
