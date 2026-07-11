use crate::report_types::StaticFlag;
use std::collections::HashMap;

use super::support;

pub(super) fn build_static_signal_maps(
    static_flags: &[StaticFlag],
) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let mut method_signals: HashMap<String, Vec<String>> = HashMap::new();
    let mut file_signals: HashMap<String, Vec<String>> = HashMap::new();

    for flag in static_flags {
        match flag.flag_type.as_str() {
            "method" => {
                if let Some(method_name) = &flag.method_name {
                    let key = support::review_key(&flag.file_path, method_name);
                    let entry = method_signals.entry(key).or_default();
                    for reason in &flag.reasons {
                        let labeled_reason = format!("[{}] {}", flag.tier.label(), reason);
                        if !entry.contains(&labeled_reason) {
                            entry.push(labeled_reason);
                        }
                    }
                }
            }
            "file" => {
                let entry = file_signals.entry(flag.file_path.clone()).or_default();
                for reason in &flag.reasons {
                    let labeled_reason = format!("[{}] {}", flag.tier.label(), reason);
                    if !entry.contains(&labeled_reason) {
                        entry.push(labeled_reason);
                    }
                }
            }
            _ => {}
        }
    }

    (method_signals, file_signals)
}
