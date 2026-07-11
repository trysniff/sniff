use colored::Colorize;

pub(super) struct RenderMode<'a> {
    pub out: bool,
    pub verbose: bool,
    pub md_lines: &'a mut Vec<String>,
}

pub(super) struct MethodRender<'a> {
    pub name: &'a str,
    pub start_line: usize,
    pub end_line: usize,
    pub reasons: &'a [(String, String)],
    pub mode: RenderMode<'a>,
}

fn emit_method_markdown(render: &mut MethodRender<'_>) {
    render.mode.md_lines.push(format!(
        "### `{}` (Lines {} to {})",
        render.name, render.start_line, render.end_line
    ));
    render.mode.md_lines.push("".to_string());
    for (tier, r) in render.reasons {
        render.mode.md_lines.push(format!("  - [{}] {}", tier, r));
    }
    render.mode.md_lines.push("".to_string());
}

fn emit_method_console(render: &MethodRender<'_>) {
    println!(
        "  {} {}",
        render.name.bold(),
        format!("(Lines {} to {})", render.start_line, render.end_line).dimmed()
    );
    for (tier, r) in render.reasons {
        println!("    {} [{}] {}", "!".yellow(), tier, r);
    }
}

pub(super) fn emit_method_reasons(render: MethodRender<'_>) {
    if render.reasons.is_empty() {
        if render.mode.verbose && !render.mode.out {
            println!("  {}  {}", "OK".green(), render.name);
        }
        return;
    }

    if render.mode.out {
        let mut render = render;
        emit_method_markdown(&mut render);
    } else {
        emit_method_console(&render);
    }
}
