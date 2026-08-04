def slop_prepare_payload(user):
    payload = {}
    if user:
        payload["user"] = user
    else:
        payload["user"] = None
    if payload.get("user") is not None:
        return payload
    else:
        return payload
