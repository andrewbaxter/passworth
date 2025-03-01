//! Paths are a concatenated sequence of `/`-prepended escaped strings. This makes
//! the representations of a path with an "empty segment", a path with two "empty
//! segments" and an "empty path" unambiguous while remaining moderately usable.
use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::str::FromStr,
};
#[cfg(feature = "native")]
use {
    aargvark::traits_impls::AargvarkFromStr,
};

struct Reader {
    i: usize,
    data: Vec<char>,
}

impl Reader {
    fn new(data: &str) -> Self {
        return Self {
            i: 0,
            data: data.chars().collect(),
        };
    }

    fn peek(&mut self) -> Option<(usize, char)> {
        if self.i >= self.data.len() {
            return None;
        }
        return Some((self.i, self.data[self.i]));
    }

    fn eat(&mut self) -> Option<(usize, char)> {
        let out = self.peek();
        self.i += 1;
        return out;
    }
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename = "snake_case", deny_unknown_fields)]
pub struct SpecificPath(pub Vec<String>);

impl SpecificPath {
    pub fn child(&self, sub: impl ToString) -> SpecificPath {
        let mut out = self.0.clone();
        out.push(sub.to_string());
        return SpecificPath(out);
    }
}

impl FromStr for SpecificPath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut path = Reader::new(s);
        let mut out = vec![];
        while let Some((i, c)) = path.eat() {
            if c != '/' {
                return Err(format!("Path segment missing leading slash at {}", i));
            }
            let mut buf = vec![];
            let mut escape = false;
            while let Some((_, c)) = path.peek() {
                if escape {
                    path.eat();
                    buf.push(c);
                    escape = false;
                } else {
                    match c {
                        '\\' => {
                            path.eat();
                            escape = true;
                        },
                        '/' => {
                            break;
                        },
                        _ => {
                            path.eat();
                            buf.push(c);
                        },
                    }
                }
            }
            out.push(buf.drain(..).collect());
        }
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

#[cfg(feature = "native")]
impl AargvarkFromStr for SpecificPath {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(<SpecificPath as FromStr>::from_str(s).map_err(|e| e.to_string())?);
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(
            vec![aargvark::help::HelpPatternElement::Type("PATH/TO/DATA".to_string())],
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut path = Reader::new(s);
        let mut out = vec![];
        while let Some((i, c)) = path.eat() {
            if c != '/' {
                return Err(format!("Path segment missing leading slash at {}", i));
            }
            let mut buf = vec![];
            let mut escape = false;
            let mut includes_wildcard = false;
            while let Some((_, c)) = path.peek() {
                if escape {
                    path.eat();
                    buf.push(c);
                    escape = false;
                } else {
                    match c {
                        '*' => {
                            path.eat();
                            includes_wildcard = true;
                            buf.push('*');
                        },
                        '\\' => {
                            path.eat();
                            escape = true;
                        },
                        '/' => {
                            break;
                        },
                        _ => {
                            path.eat();
                            buf.push(c);
                        },
                    }
                }
            }
            let seg = buf.into_iter().collect::<String>();
            if !seg.is_empty() {
                if seg.len() == 1 && includes_wildcard {
                    out.push(GlobSeg::Glob);
                } else {
                    out.push(GlobSeg::Lit(seg));
                }
            }
        }
        return Ok(Self(out));
    }
}
