use loga::ea;

/// Convert a specific path (segments) into an escaped string for database prefix
/// lookup. Each segment starts with a `/`.
pub fn specific_to_db_path(path: &[String]) -> String {
    let mut out = String::new();
    for seg in path {
        out.push_str("/");
        out.push_str(&seg.replace("\\", "\\\\").replace("/", "\\/"));
    }
    return out;
}

/// Convert a specific path (segments)
pub fn specific_from_db_path(path: &str) -> Vec<String> {
    let path = path.as_bytes();
    let mut out = vec![];
    if path.len() == 0 {
        return out;
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
                    out.push(unsafe {
                        String::from_utf8_unchecked(buf.split_off(0))
                    });
                },
                c => {
                    buf.push(c);
                },
            }
        }
    }
    out.push(unsafe {
        String::from_utf8_unchecked(buf.split_off(0))
    });
    return out;
}

pub enum GlobSeg {
    Literal(String),
    Wildcard,
}

pub fn glob_from_db_path(path: &str) -> Result<Vec<GlobSeg>, loga::Error> {
    let path1 = path.as_bytes();
    let mut out = vec![];
    if path1.len() == 0 {
        return Ok(out);
    }
    let mut buf = vec![];
    let mut escape = false;
    let mut includes_wildcard = false;
    if path1[0] != b'/' {
        return Err(loga::err_with("Path must either be empty or start with /", ea!(path = path)));
    }
    for i in 0 .. path1.len() {
        if escape {
            buf.push(path1[i]);
            escape = false;
        } else {
            match path1[i] {
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
                        out.push(GlobSeg::Wildcard);
                    } else {
                        out.push(GlobSeg::Literal(seg));
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
        out.push(GlobSeg::Wildcard);
    } else {
        out.push(GlobSeg::Literal(seg));
    }
    return Ok(out);
}
