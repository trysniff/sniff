def clean_parse_tokens(text):
    tokens = []
    current = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char.isspace() and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def clean_validate_contract(result):
    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    tier = result.get("tier")
    smelly = result.get("smelly")
    if smelly != (tier != "clean"):
        raise ValueError("tier and smelly disagree")
    return tier


def clean_extract_json_payload(content, parse, recover):
    try:
        return parse(content)
    except ValueError:
        pass
    return recover(content)


def kinda_forward_payload(payload):
    forwarded = payload
    return forwarded


def unresolved_external_boundary(value):
    return external_boundary(value)
