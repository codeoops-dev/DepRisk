//! The symbols the request asks about, indexed for matching against what the code references.

use crate::protocol::{Target, MAX_SYMBOLS_PER_TARGET, MAX_TARGETS};
use std::collections::HashMap;

pub struct Sym {
    /// The symbol as given (`Ns.Type.Member`, `Ns.Type.#ctor`, `Ns.Type.*`).
    pub text: String,
    /// Everything before the last dot.
    pub type_fq: String,
    /// None for the wildcard `*`.
    pub member: Option<String>,
    /// Indexes of the targets that listed this symbol.
    pub targets: Vec<usize>,
}

#[derive(Default)]
pub struct TargetIndex {
    pub syms: Vec<Sym>,
    by_text: HashMap<String, usize>,
    by_type: HashMap<String, Vec<usize>>,
    by_member: HashMap<String, Vec<usize>>,
    pub wildcards: Vec<usize>,
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// A symbol is dotted identifiers; the last part may also be `*` or `#ctor`. At least a type and a member.
pub fn validate_symbol(symbol: &str) -> Result<(), String> {
    if symbol.is_empty() || symbol.len() > 512 {
        return Err("symbol is empty or longer than 512 characters".to_string());
    }
    let parts: Vec<&str> = symbol.split('.').collect();
    if parts.len() < 2 {
        return Err(format!("symbol '{}' needs a type and a member (Type.Member)", crate::safe(symbol)));
    }
    let last = parts[parts.len() - 1];
    if !(is_identifier(last) || last == "*" || last == "#ctor") || !parts[..parts.len() - 1].iter().all(|p| is_identifier(p)) {
        return Err(format!("'{}' is not a valid C# symbol", crate::safe(symbol)));
    }
    Ok(())
}

impl TargetIndex {
    /// The index for C# symbols (`Namespace.Type.Member`).
    pub fn build(targets: &[Target]) -> Result<TargetIndex, String> {
        TargetIndex::build_with(targets, |symbol| {
            validate_symbol(symbol)?;
            let (type_fq, last) = symbol.rsplit_once('.').expect("validated");
            Ok((type_fq.to_string(), if last == "*" { None } else { Some(last.to_string()) }))
        })
    }

    /// The index for any language: `split` validates a symbol and splits it into its owner (the C# type, the JavaScript module and
    /// path up to the last member) and the member (`None` for a wildcard).
    pub fn build_with(targets: &[Target], split: impl Fn(&str) -> Result<(String, Option<String>), String>) -> Result<TargetIndex, String> {
        if targets.len() > MAX_TARGETS {
            return Err(format!("more than {MAX_TARGETS} targets"));
        }
        let mut index = TargetIndex::default();
        for (t, target) in targets.iter().enumerate() {
            if target.symbols.len() > MAX_SYMBOLS_PER_TARGET {
                return Err(format!("target {t} lists more than {MAX_SYMBOLS_PER_TARGET} symbols"));
            }
            for symbol in &target.symbols {
                let (type_fq, member) = split(symbol)?;
                let i = match index.by_text.get(symbol) {
                    Some(&i) => i,
                    None => {
                        let i = index.syms.len();
                        index.syms.push(Sym {
                            text: symbol.clone(),
                            type_fq: type_fq.clone(),
                            member: member.clone(),
                            targets: Vec::new(),
                        });
                        index.by_text.insert(symbol.clone(), i);
                        index.by_type.entry(type_fq).or_default().push(i);
                        match member {
                            Some(m) => index.by_member.entry(m).or_default().push(i),
                            None => index.wildcards.push(i),
                        }
                        i
                    }
                };
                if !index.syms[i].targets.contains(&t) {
                    index.syms[i].targets.push(t);
                }
            }
        }
        Ok(index)
    }

    /// Symbols that a reference to `type_fq.member` stands for: the exact symbol and the type's wildcard.
    pub fn match_external(&self, type_fq: &str, member: &str) -> Vec<usize> {
        self.by_type
            .get(type_fq)
            .map(|v| v.iter().copied().filter(|&i| self.syms[i].member.as_deref().map(|m| m == member).unwrap_or(true)).collect())
            .unwrap_or_default()
    }

    pub fn has_type(&self, type_fq: &str) -> bool {
        self.by_type.contains_key(type_fq)
    }

    pub fn type_syms(&self, type_fq: &str) -> &[usize] {
        self.by_type.get(type_fq).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn with_member(&self, member: &str) -> &[usize] {
        self.by_member.get(member).map(|v| v.as_slice()).unwrap_or(&[])
    }
}
