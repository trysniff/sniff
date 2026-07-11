package main

func ProcessData(values []string) []string {
    cleaned := make([]string, 0, len(values))
    for _, value := range values {
        cleaned = append(cleaned, value)
    }
    return cleaned
}
