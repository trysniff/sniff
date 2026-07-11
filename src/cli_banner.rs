const BANNER: &str = r#"
       ______      ______
    .-'      '-.__-'      '-.
  .'          .--.          '.
 /           (    )           \
|            (    )            |
|             '--'             |
 \                           /
  '.                       .'
    '-.__________________.-'
"#;

pub(crate) fn print() {
    eprintln!("{}", BANNER.trim_matches('\n'));
}

#[cfg(test)]
mod tests {
    use super::BANNER;

    #[test]
    fn banner_has_the_snout_shape() {
        assert!(BANNER.contains("______"));
        assert!(BANNER.contains("(    )"));
        assert!(BANNER.contains("__.-"));
    }
}
