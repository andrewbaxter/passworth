use {
    loga::{
        ea,
        Log,
    },
    passworth_native::config::latest::{
        ConfigAuthFactor,
        ConfigAuthFactorVariant,
        ConfigCredSmartcards,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        sync::Arc,
    },
};

#[derive(PartialEq)]
pub struct FactorTree {
    pub id: String,
    pub desc: String,
    pub variant: FactorTreeVariant,
}

#[derive(PartialEq)]
pub enum FactorTreeVariant {
    And(Vec<Arc<FactorTree>>),
    Or(Vec<Arc<FactorTree>>),
    Password,
    Smartcards(ConfigCredSmartcards),
    RecoveryPhrase,
}

pub fn build_factor_tree(
    seen: &HashSet<String>,
    config_factors: &HashMap<String, &ConfigAuthFactor>,
    out_factors: &mut HashMap<String, Arc<FactorTree>>,
    at_id: &String,
) -> Result<Arc<FactorTree>, loga::Error> {
    let log = Log::new().fork(ea!(factor = at_id));
    let Some(at) = config_factors.get(at_id) else {
        return Err(log.err("Unknown factor id referenced by method or another factor"));
    };
    if seen.contains(at_id) {
        return Err(log.err("An auth factor directly or indirectly depends on itself"));
    }
    let mut seen = seen.clone();
    seen.insert(at_id.clone());
    let variant;
    match &at.variant {
        ConfigAuthFactorVariant::And(children) => {
            let mut out = vec![];
            let mut errs = vec![];
            if children.is_empty() {
                return Err(log.err("Factor's child list is empty"));
            }
            for child_id in children {
                match build_factor_tree(&seen, config_factors, out_factors, &child_id) {
                    Ok(c) => out.push(c),
                    Err(e) => {
                        errs.push(e);
                    },
                }
            }
            if !errs.is_empty() {
                return Err(log.agg_err("Errors processing children of factor", errs));
            }
            variant = FactorTreeVariant::And(out);
        },
        ConfigAuthFactorVariant::Or(children) => {
            let mut out = vec![];
            let mut errs = vec![];
            if children.is_empty() {
                return Err(log.err("Factor's child list is empty"));
            }
            for child_id in children {
                match build_factor_tree(&seen, config_factors, out_factors, &child_id) {
                    Ok(c) => out.push(c),
                    Err(e) => {
                        errs.push(e);
                    },
                }
            }
            if !errs.is_empty() {
                return Err(log.agg_err("Errors processing children of factor", errs));
            }
            variant = FactorTreeVariant::Or(out);
        },
        ConfigAuthFactorVariant::Password => {
            variant = FactorTreeVariant::Password;
        },
        ConfigAuthFactorVariant::Smartcards(s) => {
            variant = FactorTreeVariant::Smartcards(s.clone());
        },
        ConfigAuthFactorVariant::RecoveryCode => {
            variant = FactorTreeVariant::RecoveryPhrase;
        },
    };
    let out = Arc::new(FactorTree {
        id: at.id.clone(),
        desc: at.description.clone(),
        variant: variant,
    });
    out_factors.insert(at_id.clone(), out.clone());
    return Ok(out);
}
