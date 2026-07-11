package demo

fun processData(values: List<String>): List<String> {
    return values.map { value -> value.trim() }
}
