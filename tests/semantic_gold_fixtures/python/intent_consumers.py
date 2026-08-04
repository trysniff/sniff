from .intent_contracts import (
    emit_event,
    resolve_preview_rationale_lines,
    run_with_clock,
    stable_load,
)


def load_for_request(key):
    return stable_load(key)


def run_deterministically(task):
    return run_with_clock(task, lambda: 42.0)


def publish(event, publisher=emit_event):
    return publisher(event)


def plan_release(
    release_label,
    recommendations,
    target_sha,
    resolve_preview_rationale_lines_fn,
):
    return resolve_preview_rationale_lines_fn(
        release_label=release_label,
        recommendations=recommendations,
        target_sha=target_sha,
    )


def render_release_rationale(release_label, recommendations, target_sha):
    return plan_release(
        release_label,
        recommendations,
        target_sha,
        resolve_preview_rationale_lines_fn=resolve_preview_rationale_lines,
    )
