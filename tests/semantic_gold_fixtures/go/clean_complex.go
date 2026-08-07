package gold

type Payload struct{}

var (
	_ = cleanParseTokens("")
	_ = cleanValidateContract(map[string]any{"tier": "clean", "smelly": false})
	_ = kindaForwardPayload(Payload{})
)

func cleanParseTokens(text string) []string {
	tokens := []string{}
	current := []rune{}
	quoted := false
	escaped := false
	for _, ch := range text {
		if escaped {
			current = append(current, ch)
			escaped = false
		} else if ch == '\\' {
			current = append(current, ch)
			escaped = true
		} else if ch == '"' {
			current = append(current, ch)
			quoted = !quoted
		} else if ch == ' ' && !quoted {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = nil
			}
		} else {
			current = append(current, ch)
		}
	}
	if len(current) > 0 {
		tokens = append(tokens, string(current))
	}
	return tokens
}

func cleanValidateContract(result map[string]any) string {
	tier, _ := result["tier"].(string)
	smelly, _ := result["smelly"].(bool)
	if smelly != (tier != "clean") {
		panic("tier and smelly disagree")
	}
	return tier
}

func kindaForwardPayload(payload Payload) Payload {
	forwarded := payload
	return forwarded
}
