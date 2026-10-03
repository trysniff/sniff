use serde::Deserialize;
use serde::de::{self, Error as _, MapAccess, SeqAccess, Visitor};

pub(super) fn parse(bytes: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(UniqueJson(number.into()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(UniqueJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJson(values.into()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
            if values.insert(key, value).is_some() {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueJson(values.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn unique_values_preserve_numbers_nulls_strings_and_separate_objects() {
        let bytes = br#"[18446744073709551615,-9223372036854775808,1.25,true,null,"\u00e9",{"x":1},{"x":2}]"#;
        assert_eq!(
            parse(bytes).unwrap(),
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
        );
    }

    #[test]
    fn decoded_equivalent_keys_and_nested_ignored_objects_are_not_unique() {
        for bytes in [
            br#"{"isPrivate":false,"is\u0050rivate":true}"#.as_slice(),
            br#"{"extensions":{"nested":[{"x":1,"x":1}]}}"#,
        ] {
            assert!(
                parse(bytes)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate JSON object key")
            );
        }
    }

    #[test]
    fn malformed_nonfinite_trailing_and_deep_inputs_fail() {
        for bytes in [
            b"{} {}".as_slice(),
            b"NaN",
            b"Infinity",
            b"1e999",
            b"\xff",
            b"{",
        ] {
            assert!(parse(bytes).is_err());
        }
        let deep = format!("{}null{}", "[".repeat(140), "]".repeat(140));
        assert!(parse(deep.as_bytes()).is_err());
    }
}
