use {
    aargvark::traits_impls::AargvarkFromStr,
    loga::ea,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::str::FromStr,
};

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename = "snake_case", deny_unknown_fields)]
pub struct SpecificPath(pub Vec<String>);

impl FromStr for SpecificPath {
    type Err = loga::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = s.as_bytes();
        let mut out = vec![];
        if path.len() == 0 {
            return Ok(SpecificPath(out));
        }
        let mut buf = vec![];
        let mut escape = false;
        if path[0] != b'/' {
            panic!();
        }
        for i in 1 .. path.len() {
            if escape {
                buf.push(path[i]);
                escape = false;
            } else {
                match path[i] {
                    b'\\' => {
                        escape = true;
                    },
                    b'/' => {
                        out.push(String::from_utf8(buf.split_off(0)).unwrap());
                    },
                    c => {
                        buf.push(c);
                    },
                }
            }
        }
        out.push(String::from_utf8(buf).unwrap());
        return Ok(SpecificPath(out));
    }
}

impl ToString for SpecificPath {
    fn to_string(&self) -> String {
        let mut out = String::new();
        for seg in &self.0 {
            out.push_str("/");
            out.push_str(&seg.replace("\\", "\\\\").replace("/", "\\/"));
        }
        return out;
    }
}

impl AargvarkFromStr for SpecificPath {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(SpecificPath(serde_json::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(
            vec![aargvark::help::HelpPatternElement::Type("/PATH/TO/DATA".to_string())],
        );
    }
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename = "snake_case", deny_unknown_fields)]
pub enum GlobSeg {
    Lit(String),
    Glob,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename = "snake_case", deny_unknown_fields)]
pub struct GlobPath(pub Vec<GlobSeg>);

impl FromStr for GlobPath {
    type Err = loga::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = s.as_bytes();
        let mut out = vec![];
        if path.len() == 0 {
            return Ok(Self(out));
        }
        let mut buf = vec![];
        let mut escape = false;
        let mut includes_wildcard = false;
        if path[0] != b'/' {
            return Err(loga::err_with("Path must either be empty or start with /", ea!(path = s)));
        }
        for i in 0 .. path.len() {
            if escape {
                buf.push(path[i]);
                escape = false;
            } else {
                match path[i] {
                    b'*' => {
                        includes_wildcard = true;
                        buf.push(b'*');
                    },
                    b'\\' => {
                        escape = true;
                    },
                    b'/' => {
                        let seg = unsafe {
                            String::from_utf8_unchecked(buf.split_off(0))
                        };
                        if seg.len() == 1 && includes_wildcard {
                            out.push(GlobSeg::Glob);
                        } else {
                            out.push(GlobSeg::Lit(seg));
                        }
                        includes_wildcard = false;
                    },
                    c => {
                        buf.push(c);
                    },
                }
            }
        }
        let seg = unsafe {
            String::from_utf8_unchecked(buf.split_off(0))
        };
        if seg.len() == 1 && includes_wildcard {
            out.push(GlobSeg::Glob);
        } else {
            out.push(GlobSeg::Lit(seg));
        }
        return Ok(Self(out));
    }
}
