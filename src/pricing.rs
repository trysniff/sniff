use std::env;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PricingRates {
    pub input_per_million: f64,
    pub cached_input_per_million: f64,
    pub output_per_million: f64,
}

impl PricingRates {
    pub fn from_env() -> Self {
        Self {
            input_per_million: configured_rate("SNIFF_INPUT_COST_PER_MILLION", 0.14),
            cached_input_per_million: configured_rate(
                "SNIFF_CACHED_INPUT_COST_PER_MILLION",
                0.0028,
            ),
            output_per_million: configured_rate("SNIFF_OUTPUT_COST_PER_MILLION", 0.28),
        }
    }

    pub fn cost(
        self,
        input_tokens: usize,
        cached_input_tokens: usize,
        output_tokens: usize,
    ) -> f64 {
        let cached_input_tokens = cached_input_tokens.min(input_tokens);
        let cache_miss_input_tokens = input_tokens - cached_input_tokens;
        (cache_miss_input_tokens as f64 / 1_000_000.0) * self.input_per_million
            + (cached_input_tokens as f64 / 1_000_000.0) * self.cached_input_per_million
            + (output_tokens as f64 / 1_000_000.0) * self.output_per_million
    }
}

fn configured_rate(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::PricingRates;

    #[test]
    fn prices_cached_input_separately() {
        let rates = PricingRates {
            input_per_million: 1.0,
            cached_input_per_million: 0.1,
            output_per_million: 2.0,
        };

        assert_eq!(rates.cost(1_000_000, 750_000, 500_000), 1.325);
    }

    #[test]
    fn cached_tokens_cannot_exceed_total_input() {
        let rates = PricingRates {
            input_per_million: 1.0,
            cached_input_per_million: 0.1,
            output_per_million: 2.0,
        };

        assert_eq!(rates.cost(100, 200, 0), 0.00001);
    }
}
