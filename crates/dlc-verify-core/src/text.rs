//! Plain-text rendering of JSON values as an indented outline.

use serde_json::Value;

/// Renders `value` as an indented `key: value` outline.
pub fn outline(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("-".to_owned()),
        Value::Bool(flag) => Some(if *flag { "yes" } else { "no" }.to_owned()),
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(text.clone()),
        Value::Array(items) if items.is_empty() => Some("(none)".to_owned()),
        Value::Array(items)
            if items
                .iter()
                .all(|item| !item.is_object() && !item.is_array()) =>
        {
            Some(
                items
                    .iter()
                    .filter_map(scalar)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        }
        Value::Object(map) if map.is_empty() => Some("(none)".to_owned()),
        _ => None,
    }
}

fn write_value(out: &mut String, value: &Value, depth: usize) {
    let pad = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let key = key.replace('_', " ");
                match scalar(item) {
                    Some(text) => out.push_str(&format!("{pad}{key}: {text}\n")),
                    None => {
                        out.push_str(&format!("{pad}{key}:\n"));
                        write_value(out, item, depth + 1);
                    }
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                match scalar(item) {
                    Some(text) => out.push_str(&format!("{pad}- {text}\n")),
                    None => {
                        out.push_str(&format!("{pad}[{index}]\n"));
                        write_value(out, item, depth + 1);
                    }
                }
            }
        }
        other => {
            if let Some(text) = scalar(other) {
                out.push_str(&format!("{pad}{text}\n"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outlines_nested_values() {
        let value = serde_json::json!({
            "fee_rate": 2,
            "flags": ["a", "b"],
            "inputs": [{"serial_id": 1}],
            "empty": [],
        });
        assert_eq!(
            outline(&value),
            "fee rate: 2\nflags: a, b\ninputs:\n  [0]\n    serial id: 1\nempty: (none)\n"
        );
    }
}
