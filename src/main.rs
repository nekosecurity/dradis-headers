use colored::Colorize;
use rayon::prelude::*;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;

mod cli;
use cli::cli;

#[derive(Debug)]
struct Dradis {
    sec_headers: HashMap<String, String>,
}

impl Dradis {
    fn has_header(&mut self, data: String) {
        for (key, _) in self.sec_headers.clone() {
            if data.contains(&key) {
                if self.sec_headers.get(&key).unwrap().eq("Yes") {
                    continue;
                }
                let _ = &self
                    .sec_headers
                    .insert(key.to_string(), String::from("Yes"));
            }
        }
    }

    fn populatate_header() -> HashMap<String, String> {
        const SEC_HEADERS: [&str; 12] = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "X-Permitted-Cross-Domain-Policies",
            "Referrer-Policy",
            "Permission-Policy",
            "Clear-Site-Data",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Cache-Control",
        ];
        let mut headers: HashMap<String, String> = HashMap::with_capacity(SEC_HEADERS.len());
        for header in SEC_HEADERS {
            headers
                .entry(String::from(header))
                .or_insert(String::from("No"));
        }
        return headers;
    }

    fn print_to_dradis_format(&self, host: &str) {
        println!("[+] Dradis formated output of headers for host: {}", host);
        for (key, value) in self.sec_headers.clone() {
            print!("|{key}|");
            match value.as_ref() {
                "No" => {
                    println!("{}|", format!("{value}").red())
                }
                "Yes" => {
                    println!("{}|", format!("{value}").green())
                }
                _ => {}
            }
        }
        println!("");
    }

    fn new() -> Self {
        Dradis {
            sec_headers: Dradis::populatate_header(),
        }
    }
}

fn read_bytefile(filename: &str) -> Vec<u8> {
    let file = File::open(filename);
    // Check if everything is ok
    match file {
        Ok(_) => {
            let contents = fs::read(filename);
            return contents.unwrap();
        }
        Err(e) => {
            println!("{}", e);
            exit(-1);
        }
    };
}

fn list_all_targets(contents: &Vec<u8>, scope: Option<&str>) {
    let mut hosts: Vec<String> = Vec::new();
    let regex_server_request_host: Regex = match scope {
        Some(s) => Regex::new(format!(r"Host: (.*{}.*)\s+", s).as_str()).unwrap(),
        _ => Regex::new(r"Host: (.*)\r\n").unwrap(),
    };

    println!("{:?}", regex_server_request_host);
    for part in regex_server_request_host.captures_iter(contents) {
        let host = String::from_utf8_lossy(&part[1]).to_string();
        if !hosts.contains(&host) {
            // Sometime weird hosts appear
            if !&host.starts_with("'") {
                hosts.push(host.clone());
                println!("{}", host);
            }
        }
    }
}

/// Checks if header is present in the burp file
/// # Arguments
/// * `contents` - A bytes arrays representing the burp file contents
/// * `host` - A &str representing the host to check
///
/// // First, we get all Host header then we get values only from interested host
///
fn check_headers(contents: &Vec<u8>, host: &str) {
    let mut dradis: Dradis = Dradis::new();
    let regex_server_request_host = Regex::new("Host:").unwrap();
    let mut hosts_index: Vec<_> = Vec::new();

    for part in regex_server_request_host.find_iter(&contents) {
        hosts_index.push(part.start())
    }
    for i in (0..hosts_index.len() - 1).step_by(1) {
        let data =
            String::from_utf8_lossy(&contents[hosts_index[i]..hosts_index[i + 1]]).to_string();
        if data.contains(&format!("Host: {}", host).to_string()) {
            dradis.has_header(data)
        }
    }
    dradis.print_to_dradis_format(host)
}

fn main() {
    let app: clap::ArgMatches = cli().get_matches();

    let burpfile = PathBuf::from(app.get_one::<String>("burp").unwrap());
    if !burpfile.exists() {
        println!("[!] No such file or directory");
        exit(-1);
    }
    if burpfile.extension().unwrap().ne("burp") {
        println!("[!] Error: The file must end with .burp");
        exit(-1);
    }

    let contents: Vec<u8> = read_bytefile(fs::canonicalize(&burpfile).unwrap().to_str().unwrap());
    let hosts: Vec<_> = app.get_raw("scope").unwrap().collect::<Vec<_>>();

    match app.get_one::<bool>("list-targets").unwrap() {
        true => {
            hosts
                .par_iter()
                .for_each(|host| list_all_targets(&contents, Some(host.to_str().unwrap())));

            exit(1)
        }
        _ => {
            if !hosts[0].is_empty() {
                hosts
                    .par_iter()
                    .for_each(|host| check_headers(&contents, host.to_str().unwrap()))
            } else {
                println!("The scope parameter cannot be empty");
            }
        }
    };
}
