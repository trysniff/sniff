use super::ResponseSchema;

pub(super) fn schema_description(schema: ResponseSchema) -> &'static str {
    match schema {
        ResponseSchema::MethodReview => {
            "Required fields: smelly (bool), tier (string), evidence (string), reason (string)."
        }
        ResponseSchema::FileReview => {
            "Required fields: smelly (bool), tier (string), evidence (string), cohesive (bool), name_accurate (bool), reason (string)."
        }
        ResponseSchema::RoleClassification => "Required fields: role (string), reason (string).",
    }
}

pub(super) fn validate_schema(
    value: &serde_json::Value,
    schema: ResponseSchema,
) -> Result<(), String> {
    let Some(obj) = value.as_object() else {
        return Err("response was not a JSON object".to_string());
    };

    let mut missing = Vec::new();
    let mut wrong_type = Vec::new();

    fn check_bool(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get(name) {
            Some(v) if v.is_boolean() => {}
            Some(_) => wrong_type.push(name.to_string()),
            None => missing.push(name.to_string()),
        }
    }

    fn check_string(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get(name) {
            Some(v) if v.is_string() => {}
            Some(_) => wrong_type.push(name.to_string()),
            None => missing.push(name.to_string()),
        }
    }

    match schema {
        ResponseSchema::MethodReview => {
            check_bool(obj, "smelly", &mut missing, &mut wrong_type);
            check_string(obj, "tier", &mut missing, &mut wrong_type);
            check_string(obj, "evidence", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
        }
        ResponseSchema::FileReview => {
            check_bool(obj, "smelly", &mut missing, &mut wrong_type);
            check_string(obj, "tier", &mut missing, &mut wrong_type);
            check_string(obj, "evidence", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
            check_bool(obj, "cohesive", &mut missing, &mut wrong_type);
            check_bool(obj, "name_accurate", &mut missing, &mut wrong_type);
        }
        ResponseSchema::RoleClassification => {
            check_string(obj, "role", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
        }
    }

    if missing.is_empty() && wrong_type.is_empty() {
        Ok(())
    } else {
        let mut parts = Vec::new();
        if !missing.is_empty() {
            parts.push(format!("missing fields: {}", missing.join(", ")));
        }
        if !wrong_type.is_empty() {
            parts.push(format!("wrong field types: {}", wrong_type.join(", ")));
        }
        Err(parts.join("; "))
    }
}
