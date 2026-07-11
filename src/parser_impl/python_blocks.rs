fn line_indent(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

fn looks_like_python_block_boundary(trimmed: &str) -> bool {
    trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("class ")
        || trimmed.starts_with("@")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("elif ")
        || trimmed.starts_with("else:")
        || trimmed.starts_with("for ")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("with ")
        || trimmed.starts_with("try:")
        || trimmed.starts_with("except ")
        || trimmed.starts_with("finally:")
        || trimmed.starts_with("match ")
        || trimmed.starts_with("case ")
}

pub(super) fn block_end(lines: &[&str], start: usize, base_indent: usize) -> usize {
    let mut end = lines.len().saturating_sub(1);
    for (idx, line) in lines.iter().enumerate().skip(start + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if line_indent(line) <= base_indent
            && !trimmed.starts_with('#')
            && looks_like_python_block_boundary(trimmed)
        {
            end = idx.saturating_sub(1);
            break;
        }
    }
    end
}
