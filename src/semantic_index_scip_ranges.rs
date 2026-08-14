use crate::semantic_index::{
    RepositoryPath, SemanticOccurrenceRole, SemanticPosition, SemanticPositionEncoding,
    SemanticSourceRange, SemanticTextEncoding,
};
use scip::types::{Document, Metadata, Occurrence, PositionEncoding, TextEncoding, occurrence};
use std::collections::BTreeSet;
use std::path::{Component, Path};

const KNOWN_ROLE_BITS: i32 = 1 | 2 | 4 | 8 | 16 | 32 | 64;

pub(super) fn normalize_repository_path(raw: &str) -> Result<RepositoryPath, String> {
    if raw.trim().is_empty() {
        return Err("SCIP document has an empty relative path".to_string());
    }
    let slash_normalized = raw.replace('\\', "/");
    if slash_normalized.as_bytes().get(1) == Some(&b':')
        && slash_normalized
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
    {
        return Err(format!("SCIP document path must be relative: {raw}"));
    }
    if slash_normalized.contains('\0') {
        return Err(format!("SCIP document path contains a NUL byte: {raw:?}"));
    }
    let path = Path::new(&slash_normalized);
    if path.is_absolute() {
        return Err(format!("SCIP document path must be relative: {raw}"));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| format!("SCIP document path is not valid Unicode: {raw}"))?;
                if !text.is_empty() {
                    parts.push(text);
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "SCIP document path escapes the repository root: {raw}"
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(format!("SCIP document path has no file component: {raw}"));
    }
    Ok(RepositoryPath(parts.join("/")))
}

pub(super) fn position_encoding(document: &Document) -> Result<SemanticPositionEncoding, String> {
    match document.position_encoding.value() {
        value if value == PositionEncoding::UTF8CodeUnitOffsetFromLineStart as i32 => {
            Ok(SemanticPositionEncoding::Utf8)
        }
        value if value == PositionEncoding::UTF16CodeUnitOffsetFromLineStart as i32 => {
            Ok(SemanticPositionEncoding::Utf16)
        }
        value if value == PositionEncoding::UTF32CodeUnitOffsetFromLineStart as i32 => {
            Ok(SemanticPositionEncoding::Utf32)
        }
        value if value == PositionEncoding::UnspecifiedPositionEncoding as i32 => Err(format!(
            "SCIP document {} omits its source position encoding",
            document.relative_path
        )),
        value => Err(format!(
            "SCIP document {} uses unknown position encoding {value}",
            document.relative_path
        )),
    }
}

pub(super) fn metadata_text_encoding(
    metadata: &Metadata,
) -> Result<Option<SemanticTextEncoding>, String> {
    match metadata.text_document_encoding.value() {
        value if value == TextEncoding::UTF8 as i32 => Ok(Some(SemanticTextEncoding::Utf8)),
        value if value == TextEncoding::UTF16 as i32 => Ok(Some(SemanticTextEncoding::Utf16)),
        value if value == TextEncoding::UnspecifiedTextEncoding as i32 => Ok(None),
        value => Err(format!("SCIP metadata uses unknown text encoding {value}")),
    }
}

pub(super) fn occurrence_range(occurrence: &Occurrence) -> Result<SemanticSourceRange, String> {
    let coordinates = match occurrence.typed_range.as_ref() {
        Some(occurrence::Typed_range::SingleLineRange(range)) => [
            range.line,
            range.start_character,
            range.line,
            range.end_character,
        ],
        Some(occurrence::Typed_range::MultiLineRange(range)) => [
            range.start_line,
            range.start_character,
            range.end_line,
            range.end_character,
        ],
        Some(_) => {
            return Err("SCIP occurrence uses an unsupported typed range variant".to_string());
        }
        None => match occurrence.range.as_slice() {
            [line, start, end] => [*line, *start, *line, *end],
            [start_line, start_character, end_line, end_character] => {
                [*start_line, *start_character, *end_line, *end_character]
            }
            values => {
                return Err(format!(
                    "SCIP occurrence range must contain 3 or 4 coordinates, found {}",
                    values.len()
                ));
            }
        },
    };
    checked_range(coordinates)
}

fn checked_range(coordinates: [i32; 4]) -> Result<SemanticSourceRange, String> {
    if coordinates.iter().any(|value| *value < 0) {
        return Err(format!(
            "SCIP occurrence range contains a negative coordinate: {coordinates:?}"
        ));
    }
    let start = SemanticPosition {
        line: coordinates[0] as u32,
        character: coordinates[1] as u32,
    };
    let end = SemanticPosition {
        line: coordinates[2] as u32,
        character: coordinates[3] as u32,
    };
    if end < start {
        return Err(format!(
            "SCIP occurrence range is inverted: {coordinates:?}"
        ));
    }
    Ok(SemanticSourceRange { start, end })
}

pub(super) fn occurrence_roles(role_bits: i32) -> Result<BTreeSet<SemanticOccurrenceRole>, String> {
    if role_bits < 0 || role_bits & !KNOWN_ROLE_BITS != 0 {
        return Err(format!(
            "SCIP occurrence contains unknown symbol-role bits: {role_bits}"
        ));
    }
    let mappings = [
        (1, SemanticOccurrenceRole::Definition),
        (2, SemanticOccurrenceRole::Import),
        (4, SemanticOccurrenceRole::Write),
        (8, SemanticOccurrenceRole::Read),
        (16, SemanticOccurrenceRole::Generated),
        (32, SemanticOccurrenceRole::Test),
        (64, SemanticOccurrenceRole::ForwardDefinition),
    ];
    Ok(mappings
        .into_iter()
        .filter_map(|(bit, role)| (role_bits & bit != 0).then_some(role))
        .collect())
}
