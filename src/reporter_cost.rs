use crate::config::ResolvedConfig;
use crate::report_types::RunStats;
use std::env;

fn configured_rate(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(default)
}

pub(super) fn calculate_cost(s: &RunStats, _config: &ResolvedConfig) -> String {
    let input_per_m = configured_rate("SNIFF_INPUT_COST_PER_MILLION", 0.14);
    let cached_input_per_m = configured_rate("SNIFF_CACHED_INPUT_COST_PER_MILLION", 0.0028);
    let output_per_m = configured_rate("SNIFF_OUTPUT_COST_PER_MILLION", 0.28);
    let cached_input_tokens = s.cached_input_tokens.min(s.input_tokens);
    let cache_miss_input_tokens = s.input_tokens - cached_input_tokens;
    let rate_suffix = format!(
        "; cached {cached_input_tokens}; rates ${input_per_m:.2}/M miss / ${cached_input_per_m:.4}/M cached / ${output_per_m:.2}/M out"
    );

    let cost = (cache_miss_input_tokens as f64 / 1e6) * input_per_m
        + (cached_input_tokens as f64 / 1e6) * cached_input_per_m
        + (s.output_tokens as f64 / 1e6) * output_per_m;
    if cost < 0.0001 && (s.input_tokens > 0 || s.output_tokens > 0) {
        format!(
            "<$0.0001 (Tokens: {} in / {} out{})",
            s.input_tokens, s.output_tokens, rate_suffix
        )
    } else {
        format!(
            "${:.4} (Tokens: {} in / {} out{})",
            cost, s.input_tokens, s.output_tokens, rate_suffix
        )
    }
}

#[cfg(test)]
mod tests {
    use super::calculate_cost;
    use crate::config::ResolvedConfig;
    use crate::report_types::RunStats;

    #[test]
    fn cost_summary_discloses_the_rates_used() {
        let stats = RunStats {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..RunStats::default()
        };

        let cost = calculate_cost(&stats, &ResolvedConfig::default());

        assert!(cost.contains("rates $0.14/M miss / $0.0028/M cached / $0.28/M out"));
    }

    #[test]
    fn cost_summary_prices_cached_input_separately() {
        let stats = RunStats {
            input_tokens: 1_000_000,
            cached_input_tokens: 750_000,
            ..RunStats::default()
        };

        let cost = calculate_cost(&stats, &ResolvedConfig::default());

        assert!(cost.starts_with("$0.0371"));
        assert!(cost.contains("cached 750000"));
    }
}
