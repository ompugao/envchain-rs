use rpassword::read_password;
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::EncryptionType;
use std::collections::HashMap;
use std::env;
use std::process::Command;

fn print_help(prog: &str) {
    eprintln!(
        "{prog} (Rust)

Usage:
  Add variables
    {prog} (--set|-s) [--noecho|-n] NAMESPACE ENV [ENV ..]
  Execute with variables
    {prog} NAMESPACE CMD [ARG ...]
  List namespaces
    {prog} --list
  Remove variables
    {prog} --unset NAMESPACE ENV [ENV ..]
"
    );
}

fn get_service() -> Result<SecretService<'static>, String> {
    SecretService::connect(EncryptionType::Dh)
        .map_err(|e| format!("SecretService connect failed: {e}"))
}

fn get_collection<'a>(
    ss: &'a SecretService<'a>,
) -> Result<Collection<'a>, String> {
    ss.get_default_collection()
        .map_err(|e| format!("SecretService default collection failed: {e}"))
}

fn list_namespaces() -> Result<(), String> {
    let ss = get_service()?;
    let collection = get_collection(&ss)?;
    let items: Vec<Item> = collection
        .search_items(HashMap::new())
        .map_err(|e| format!("search_items failed: {e}"))?;

    let mut namespaces: Vec<String> = items
        .into_iter()
        .filter_map(|item| {
            let attrs = item.get_attributes().ok()?;
            attrs.get("name").cloned()
        })
        .collect();
    namespaces.sort();
    namespaces.dedup();
    for ns in namespaces {
        println!("{ns}");
    }
    Ok(())
}

fn list_values(target: &str, show_value: bool) -> Result<(), String> {
    let ss = get_service()?;
    let collection = get_collection(&ss)?;
    let items: Vec<Item> = collection
        .search_items(HashMap::from([("name", target)]))
        .map_err(|e| format!("search_items failed: {e}"))?;
    if items.is_empty() {
        eprintln!(
            "WARNING: namespace `{}` not defined.\n         You can set via running `{} --set {} SOME_ENV_NAME`.\n",
            target,
            env::args().next().unwrap_or_else(|| "envchain".into()),
            target
        );
        return Ok(());
    }
    for item in items {
        let attrs = match item.get_attributes() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let Some(key) = attrs.get("key") else {
            continue;
        };
        if show_value {
            match item.get_secret() {
                Ok(secret) => {
                    let val = String::from_utf8_lossy(&secret).to_string();
                    println!("{key}={val}");
                }
                Err(_) => println!("{key}=<unavailable>"),
            }
        } else {
            println!("{key}");
        }
    }
    Ok(())
}

fn set_values(noecho: bool, name: &str, keys: &[String]) -> Result<(), String> {
    let ss = get_service()?;
    let collection = get_collection(&ss)?;
    for key in keys {
        let prompt = format!("{name}.{key}");
        let value = if noecho {
            eprint!("{prompt} (noecho):");
            read_password().map_err(|e| format!("Failed to read password: {e}"))?
        } else {
            eprint!("{prompt}: ");
            let mut buf = String::new();
            std::io::stdin()
                .read_line(&mut buf)
                .map_err(|e| format!("Failed to read line: {e}"))?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        };
        collection
            .create_item(
                key,
                HashMap::from([("name", name), ("key", key.as_str())]),
                value.as_bytes(),
                true,
                "text/plain",
            )
            .map_err(|e| format!("Failed to store secret: {e}"))?;
    }
    Ok(())
}

fn unset_values(name: &str, keys: &[String]) -> Result<(), String> {
    let ss = get_service()?;
    let collection = get_collection(&ss)?;
    for key in keys {
        let items: Vec<Item> = collection
            .search_items(HashMap::from([("name", name), ("key", key.as_str())]))
            .map_err(|e| format!("search_items failed: {e}"))?;
        for item in items {
            if let Err(e) = item.delete() {
                eprintln!("Failed to delete {name}.{key}: {e}");
            }
        }
    }
    Ok(())
}

fn exec_with(name_csv: &str, cmd: &str, args: &[String]) -> Result<(), String> {
    let ss = get_service()?;
    let collection = get_collection(&ss)?;
    for name in name_csv.split(',') {
        let items: Vec<Item> = collection
            .search_items(HashMap::from([("name", name)]))
            .map_err(|e| format!("search_items failed: {e}"))?;
        for item in items {
            let attrs = match item.get_attributes() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let Some(key) = attrs.get("key") else {
                continue;
            };
            if let Ok(secret) = item.get_secret() {
                let val = String::from_utf8_lossy(&secret).to_string();
                // SAFETY: We are the only thread running at this point before exec,
                // and we're about to replace this process with exec anyway.
                unsafe { env::set_var(key, val) };
            }
        }
    }
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| format!("exec failed: {e}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let prog = args.remove(0);
    if args.is_empty() {
        print_help(&prog);
        std::process::exit(2);
    }
    match args[0].as_str() {
        "--set" | "-s" => {
            args.remove(0);
            let mut noecho = false;
            while args.first().map(|s| s.starts_with('-')).unwrap_or(false) {
                if args[0] == "--noecho" || args[0] == "-n" {
                    noecho = true;
                    args.remove(0);
                } else {
                    eprintln!("Unknown option: {}", args[0]);
                    std::process::exit(1);
                }
            }
            if args.len() < 2 {
                print_help(&prog);
                std::process::exit(2);
            }
            let name = args.remove(0);
            if let Err(e) = set_values(noecho, &name, &args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        "--list" | "-l" => {
            args.remove(0);
            let mut show_value = false;
            let mut target: Option<String> = None;
            while let Some(arg) = args.first() {
                if arg == "-v" || arg == "--show-value" {
                    show_value = true;
                    args.remove(0);
                } else {
                    target = Some(args.remove(0));
                }
            }
            let res = if let Some(t) = target {
                list_values(&t, show_value)
            } else if show_value {
                print_help(&prog);
                std::process::exit(2);
            } else {
                list_namespaces()
            };
            if let Err(e) = res {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        "--unset" => {
            args.remove(0);
            if args.len() < 2 {
                print_help(&prog);
                std::process::exit(2);
            }
            let name = args.remove(0);
            if let Err(e) = unset_values(&name, &args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        s if s.starts_with('-') => {
            eprintln!("Unknown option {}", s);
            std::process::exit(2);
        }
        _ => {
            if args.len() < 2 {
                print_help(&prog);
                std::process::exit(2);
            }
            let name_csv = args.remove(0);
            let cmd = args.remove(0);
            if let Err(e) = exec_with(&name_csv, &cmd, &args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}
