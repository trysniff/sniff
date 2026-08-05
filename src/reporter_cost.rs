use crate::config::ResolvedConfig;
use crate::pricing::PricingRates;
use crate::report_types::RunStats;

pub(super) fn calculate_cost(s: &RunStats, _config: &ResolvedConfig) -> String {
    let rates = PricingRates::from_env();
    let input_per_m = rates.input_per_million;
    let cached_input_per_m = rates.cached_input_per_million;
    let output_per_m = rates.output_per_million;
    let cached_input_tokens = s.cached_input_tokens.min(s.input_tokens);
    let rate_suffix = format!(
        "; cached {cached_input_tokens}; rates ${input_per_m:.2}/M miss / ${cached_input_per_m:.4}/M cached / ${output_per_m:.2}/M out"
    );

    let cost = rates.cost(s.input_tokens, cached_input_tokens, s.output_tokens);
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
