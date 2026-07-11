pub fn process_data(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.trim().to_string()).collect()
}
