use std::time::Instant;

pub(super) struct DiagnosticTiming {
    label: &'static str,
    phase: &'static str,
    context: Option<String>,
    started: Option<Instant>,
}

impl DiagnosticTiming {
    pub(super) fn new(label: &'static str, phase: &'static str) -> Self {
        Self::with_context(label, phase, String::new)
    }

    pub(super) fn with_context(
        label: &'static str,
        phase: &'static str,
        context: impl FnOnce() -> String,
    ) -> Self {
        let enabled = std::env::var("SNIFF_BENCH_SEMANTIC_TIMING").as_deref() == Ok("1");
        let context = enabled.then(context);
        let started = enabled.then(Instant::now);
        if started.is_some() {
            eprintln!(
                "sniffbench diagnostic timing label={label} phase={phase} context={} event=start",
                context.as_deref().unwrap_or_default()
            );
        }
        Self {
            label,
            phase,
            context,
            started,
        }
    }
}

impl Drop for DiagnosticTiming {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            eprintln!(
                "sniffbench diagnostic timing label={} phase={} context={} phase_ms={}",
                self.label,
                self.phase,
                self.context.as_deref().unwrap_or_default(),
                started.elapsed().as_millis()
            );
        }
    }
}
