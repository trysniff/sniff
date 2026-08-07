package gold

class Payload

fun cleanParseTokens(text: String): List<String> {
    val tokens = mutableListOf<String>()
    val current = StringBuilder()
    var quoted = false
    var escaped = false
    for (ch in text) {
        when {
            escaped -> {
                current.append(ch)
                escaped = false
            }
            ch == '\\' -> {
                current.append(ch)
                escaped = true
            }
            ch == '"' -> {
                current.append(ch)
                quoted = !quoted
            }
            ch.isWhitespace() && !quoted -> {
                if (current.isNotEmpty()) {
                    tokens += current.toString()
                    current.clear()
                }
            }
            else -> current.append(ch)
        }
    }
    if (current.isNotEmpty()) tokens += current.toString()
    return tokens
}

fun cleanValidateContract(result: Map<String, Any?>): String {
    val tier = result["tier"] as? String ?: ""
    val smelly = result["smelly"] as? Boolean ?: false
    if (smelly != (tier != "clean")) {
        error("tier and smelly disagree")
    }
    return tier
}

fun kindaForwardPayload(payload: Payload): Payload {
    val forwarded = payload
    return forwarded
}
