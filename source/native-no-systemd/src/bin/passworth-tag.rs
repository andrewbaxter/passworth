use {
    aargvark::{
        traits_impls::AargvarkFromStr,
        vark,
        Aargvark,
    },
    loga::fatal,
    nix::unistd::execv,
    passworth::ipc,
    passworth_shared_native::proto::req,
    std::ffi::CString,
};

const SEP: &str = "--";

struct Sep;

impl AargvarkFromStr for Sep {
    fn from_str(s: &str) -> Result<Self, String> {
        if s == SEP {
            return Ok(Self);
        } else {
            return Err(format!("Expected [{}]", SEP));
        }
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(vec!{
            aargvark::help::HelpPatternElement::Literal(format!("{}", SEP))
        });
    }
}

#[derive(Aargvark)]
struct Args {
    tags: Vec<aargvark::traits_impls::NotFlag>,
    #[allow(dead_code)]
    sep: Sep,
    command: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match async {
        let args = vark::<Args>();
        if args.tags.is_empty() {
            return Err(loga::err("This command was invoked with no tags")) as Result<(), _>;
        }
        if args.command.is_empty() {
            return Err(loga::err("This command was invoked with no sub-commandline"));
        }
        req(ipc::ReqTag(args.tags.into_iter().map(|x| x.0).collect::<Vec<_>>())).await?;
        let command = args.command.into_iter().map(|x| CString::new(x).unwrap()).collect::<Vec<_>>();
        execv(&command[0], &command)?;
        unreachable!();
    }.await {
        Ok(_) => { },
        Err(e) => {
            fatal(e);
        },
    }
}
