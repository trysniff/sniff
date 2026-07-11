pub(crate) fn control_flow_line_counts(source: &str) -> (usize, usize) {
    let mut branches = 0usize;
    let mut loops = 0usize;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if is_branch_line(trimmed) {
            branches += 1;
        }
        if is_loop_line(trimmed) {
            loops += 1;
        }
    }

    (branches, loops)
}

fn is_branch_line(line: &str) -> bool {
    line.starts_with("if ")
        || line.starts_with("if(")
        || line.starts_with("elif ")
        || line.starts_with("else if ")
        || line.starts_with("match ")
        || line.starts_with("switch ")
        || line.starts_with("case ")
        || line.starts_with("when ")
}

fn is_loop_line(line: &str) -> bool {
    line.starts_with("for ")
        || line.starts_with("for(")
        || line.starts_with("while ")
        || line.starts_with("while(")
        || line.starts_with("loop ")
        || line.starts_with("do ")
}
