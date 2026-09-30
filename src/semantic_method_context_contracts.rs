use crate::semantic_index::{
    SemanticIndex, SemanticRelationship, SemanticRelationshipKind, SemanticResolution,
    SemanticSymbolId, SemanticTestRelationship, SemanticUnresolvedReason,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct CompilerContracts<'a> {
    relationships: BTreeMap<&'a SemanticSymbolId, Vec<&'a SemanticRelationship>>,
    tests: BTreeMap<&'a SemanticSymbolId, Vec<&'a SemanticTestRelationship>>,
}

impl<'a> CompilerContracts<'a> {
    pub(super) fn new(index: &'a SemanticIndex) -> Self {
        let mut relationships: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for link in &index.relationships {
            relationships.entry(&link.source).or_default().push(link);
            if link.target != link.source {
                relationships.entry(&link.target).or_default().push(link);
            }
        }
        let mut tests: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for link in &index.test_relationships {
            tests.entry(&link.test).or_default().push(link);
            if let SemanticResolution::Resolved { value } = &link.production
                && value != &link.test
            {
                tests.entry(value).or_default().push(link);
            }
        }
        Self {
            relationships,
            tests,
        }
    }

    pub(super) fn render(
        &self,
        index: &SemanticIndex,
        method: &SemanticSymbolId,
        lines: &mut Vec<String>,
    ) {
        let mut facts = BTreeSet::new();
        let mut has_relationships =
            self.render_relationships(index, method, "method", false, &mut facts);
        match index
            .symbols
            .get(method)
            .and_then(|symbol| symbol.owner.as_ref())
        {
            Some(SemanticResolution::Resolved { value }) => {
                facts.insert(format!(
                    "compiler enclosing symbol: {}",
                    symbol_label(index, value)
                ));
                render_signatures(index, value, &mut facts);
                has_relationships |=
                    self.render_relationships(index, value, "enclosing symbol", true, &mut facts);
            }
            Some(SemanticResolution::Unresolved {
                reason,
                raw_target,
                detail,
            }) => {
                facts.insert(format!(
                    "compiler enclosing symbol: {}",
                    unresolved_label(*reason, raw_target.as_deref(), detail)
                ));
            }
            None => {
                facts.insert("compiler enclosing symbol: not reported".to_string());
            }
        }
        if !has_relationships {
            facts.insert("compiler contract links: not established by this index".to_string());
        }
        lines.extend(facts);

        if let Some(links) = self.tests.get(method) {
            for link in links {
                let production = match &link.production {
                    SemanticResolution::Resolved { value } => symbol_label(index, value),
                    SemanticResolution::Unresolved {
                        reason,
                        raw_target,
                        detail,
                    } => unresolved_label(*reason, raw_target.as_deref(), detail),
                };
                lines.push(format!(
                    "compiler test relationship: {} --{:?}--> {production}",
                    symbol_label(index, &link.test),
                    link.kind,
                ));
            }
        } else {
            lines.push(
                "compiler test linkage: not established by this index; not proof that tests are absent"
                    .to_string(),
            );
        }
    }

    fn render_relationships(
        &self,
        index: &SemanticIndex,
        symbol: &SemanticSymbolId,
        scope: &str,
        enclosing: bool,
        facts: &mut BTreeSet<String>,
    ) -> bool {
        let mut rendered = false;
        for link in self.relationships.get(symbol).into_iter().flatten() {
            // Enclosing namespace references are not contracts for every method it contains.
            if enclosing && link.kind == SemanticRelationshipKind::Reference {
                continue;
            }
            rendered = true;
            facts.insert(format!(
                "compiler {scope} relationship: {} --{:?}--> {}",
                symbol_label(index, &link.source),
                link.kind,
                symbol_label(index, &link.target),
            ));
            let other = if &link.source == symbol {
                &link.target
            } else {
                &link.source
            };
            render_signatures(index, other, facts);
        }
        rendered
    }
}

fn render_signatures(index: &SemanticIndex, id: &SemanticSymbolId, facts: &mut BTreeSet<String>) {
    if let Some(symbol) = index.symbols.get(id) {
        for signature in &symbol.signatures {
            facts.insert(format!(
                "compiler related signature {}: {}",
                symbol_label(index, id),
                signature.text,
            ));
        }
    }
}

fn unresolved_label(
    reason: SemanticUnresolvedReason,
    raw_target: Option<&str>,
    detail: &str,
) -> String {
    match raw_target {
        Some(target) => format!("unresolved ({reason:?}), raw target {target:?}: {detail}"),
        None => format!("unresolved ({reason:?}): {detail}"),
    }
}

fn symbol_label(index: &SemanticIndex, id: &SemanticSymbolId) -> String {
    match index
        .symbols
        .get(id)
        .and_then(|symbol| symbol.display_name.as_deref())
    {
        Some(name) => format!("{name:?} [{}]", id.0),
        None => id.0.clone(),
    }
}
