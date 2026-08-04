__all__ = ["public_unused_boundary"]


def _canonical_transform(value: str) -> str:
    return value.strip()


def _stale_private_delegate(value: str) -> str:
    return _canonical_transform(value)


def public_unused_boundary(value: str) -> str:
    return _canonical_transform(value)
