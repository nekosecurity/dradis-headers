use clap::{Arg, Command};

pub fn cli() -> Command {
    Command::new("DradisHeader")
        .version("0.1")
        .author("NekoSecurity")
        .about("Parsing burp file and find HTTP Security Headers")
        .arg(
            Arg::new("scope")
                .long("scope")
                .short('s')
                .required(true)
                .num_args(1..)
                .value_terminator("--")
                .default_value("")
                .help("Domains and/or IP list delimited by space\n"),
        )
        .arg(
            Arg::new("burp")
                .long("burp")
                .short('b')
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("The burp file containing all your pentest requests !")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("list-targets")
                .long("list-targets")
                .required(false)
                .action(clap::ArgAction::SetTrue)
                .help("List targets based on scope. Use scope='*' for list all targets"),
        )
}
