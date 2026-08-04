const BANNER: &str = r#"
 ________  ________   ___  ________ ________
|\   ____\|\   ___  \|\  \|\  _____\\  _____\
\ \  \___|\ \  \\ \  \ \  \ \  \__/\ \  \__/
 \ \_____  \ \  \\ \  \ \  \ \   __\\ \   __\
  \|____|\  \ \  \\ \  \ \  \ \  \_| \ \  \_|
    ____\_\  \ \__\\ \__\ \__\ \__\   \ \__\
   |\_________\|__| \|__|\|__|\|__|    \|__|
   \|_________|


"#;

pub(crate) fn print() {
    eprintln!("{}", BANNER.trim_matches('\n'));
}

#[cfg(test)]
mod tests {
    use super::BANNER;

    #[test]
    fn banner_contains_the_cli_mark() {
        assert!(BANNER.contains(r"|\   ____\|\   ___"));
        assert!(BANNER.contains(r"\|_________|"));
    }
}
