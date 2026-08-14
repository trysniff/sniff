use crate::types::{FileRecord, MethodRecord};
use syn::spanned::Spanned;

pub(super) fn method_info(
    file: &FileRecord,
    method: &MethodRecord,
) -> Option<(u32, Option<String>)> {
    if !file.language.eq_ignore_ascii_case("rust") {
        return None;
    }
    let ast = syn::parse_file(&file.source).ok()?;
    let mut visitor = RustCfgVisitor {
        target_line: method.start_line,
        definition_line: None,
        excluded_context: None,
        exclusion: None,
    };
    syn::visit::Visit::visit_file(&mut visitor, &ast);
    visitor
        .definition_line
        .and_then(|line| u32::try_from(line.saturating_sub(1)).ok())
        .map(|line| (line, visitor.exclusion))
}

struct RustCfgVisitor {
    target_line: usize,
    definition_line: Option<usize>,
    excluded_context: Option<String>,
    exclusion: Option<String>,
}

impl RustCfgVisitor {
    fn enter_attributes(&mut self, attrs: &[syn::Attribute]) -> Option<String> {
        let previous = self.excluded_context.clone();
        if self.excluded_context.is_none() {
            self.excluded_context = excluded_by_active_cfg(attrs);
        }
        previous
    }

    fn visit_callable(
        &mut self,
        node_start_line: usize,
        identifier_line: usize,
        attrs: &[syn::Attribute],
    ) {
        if node_start_line == self.target_line || identifier_line == self.target_line {
            self.definition_line = Some(identifier_line);
            self.exclusion = self
                .excluded_context
                .clone()
                .or_else(|| excluded_by_active_cfg(attrs));
        }
    }
}

fn excluded_by_active_cfg(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attribute| {
        let list = attribute
            .path()
            .is_ident("cfg")
            .then(|| attribute.meta.require_list().ok())??;
        let predicate = syn::parse2::<syn::Meta>(list.tokens.clone()).ok()?;
        (evaluate_cfg(&predicate) == Some(false)).then(|| {
            format!(
                "cfg({}) is inactive for the current Rust SCIP target",
                list.tokens
            )
        })
    })
}

fn evaluate_cfg(predicate: &syn::Meta) -> Option<bool> {
    match predicate {
        syn::Meta::Path(path) if path.is_ident("test") => Some(false),
        syn::Meta::Path(path) if path.is_ident("windows") => Some(cfg!(windows)),
        syn::Meta::Path(path) if path.is_ident("unix") => Some(cfg!(unix)),
        syn::Meta::Path(path) if path.is_ident("debug_assertions") => Some(cfg!(debug_assertions)),
        syn::Meta::Path(_) => None,
        syn::Meta::NameValue(value) => evaluate_cfg_name_value(value),
        syn::Meta::List(list) if list.path.is_ident("all") => evaluate_cfg_list(list, true),
        syn::Meta::List(list) if list.path.is_ident("any") => evaluate_cfg_list(list, false),
        syn::Meta::List(list) if list.path.is_ident("not") => {
            let values = parse_cfg_list(list)?;
            (values.len() == 1)
                .then(|| evaluate_cfg(&values[0]))
                .flatten()
                .map(|value| !value)
        }
        syn::Meta::List(_) => None,
    }
}

fn evaluate_cfg_name_value(value: &syn::MetaNameValue) -> Option<bool> {
    let syn::Expr::Lit(expression) = &value.value else {
        return None;
    };
    let syn::Lit::Str(expected) = &expression.lit else {
        return None;
    };
    let actual = if value.path.is_ident("target_os") {
        Some(std::env::consts::OS)
    } else if value.path.is_ident("target_arch") {
        Some(std::env::consts::ARCH)
    } else if value.path.is_ident("target_family") {
        if cfg!(windows) {
            Some("windows")
        } else if cfg!(unix) {
            Some("unix")
        } else {
            None
        }
    } else if value.path.is_ident("target_env") {
        active_target_env()
    } else {
        None
    }?;
    Some(actual == expected.value())
}

fn active_target_env() -> Option<&'static str> {
    if cfg!(target_env = "msvc") {
        Some("msvc")
    } else if cfg!(target_env = "gnu") {
        Some("gnu")
    } else if cfg!(target_env = "musl") {
        Some("musl")
    } else if cfg!(target_env = "sgx") {
        Some("sgx")
    } else if cfg!(target_env = "uclibc") {
        Some("uclibc")
    } else {
        None
    }
}

fn evaluate_cfg_list(list: &syn::MetaList, all: bool) -> Option<bool> {
    let values = parse_cfg_list(list)?;
    if all {
        if values
            .iter()
            .any(|value| evaluate_cfg(value) == Some(false))
        {
            Some(false)
        } else if values.iter().all(|value| evaluate_cfg(value) == Some(true)) {
            Some(true)
        } else {
            None
        }
    } else if values.iter().any(|value| evaluate_cfg(value) == Some(true)) {
        Some(true)
    } else if values
        .iter()
        .all(|value| evaluate_cfg(value) == Some(false))
    {
        Some(false)
    } else {
        None
    }
}

fn parse_cfg_list(list: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    use syn::parse::Parser;
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .map(|values| values.into_iter().collect())
}

impl<'ast> syn::visit::Visit<'ast> for RustCfgVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.excluded_context = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_impl(self, node);
        self.excluded_context = previous;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_trait(self, node);
        self.excluded_context = previous;
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_foreign_mod(self, node);
        self.excluded_context = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_fn(self, node);
        self.excluded_context = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_impl_item_fn(self, node);
        self.excluded_context = previous;
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_trait_item_fn(self, node);
        self.excluded_context = previous;
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        syn::visit::visit_foreign_item_fn(self, node);
    }
}
