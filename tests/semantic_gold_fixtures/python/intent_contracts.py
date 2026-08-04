from typing import Callable, Protocol


def resolve_preview_rationale_lines(
    *,
    release_label=None,
    recommendations=None,
    target_sha="HEAD",
    model=None,
    fallback_model=None,
    models_endpoint=None,
    models_token=None,
    max_retries=3,
    request_timeout=45,
    post_json_request_fn=None,
    notes=None,
):
    _ = (
        model,
        fallback_model,
        models_endpoint,
        models_token,
        max_retries,
        request_timeout,
        post_json_request_fn,
        notes,
    )
    return build_release_why_lines(release_label, recommendations, target_sha)


def extract_signature(lines):
    indent = 0
    for line in lines:
        if line.startswith("def "):
            if indent == 0:
                return line
    return None


def choose_payload(enabled, payload):
    if enabled:
        return payload
    return payload


def _load_impl(key):
    return {"key": key}


def stable_load(key):
    """Stable public loading boundary used by callers."""
    return _load_impl(key)


def run_with_clock(task, clock: Callable[[], float]):
    return task(clock())


def emit_event(event):
    return {"event": event}


def call_model(client, payload):
    try:
        return client.complete(payload)
    except TimeoutError:
        return client.complete(payload)
    except ValueError as error:
        raise RuntimeError("provider rejected the payload") from error


def unresolved_external_boundary(value):
    return external_package.transform(value)


class Store(Protocol):
    def metadata(self, key):
        ...
