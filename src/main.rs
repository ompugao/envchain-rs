mod backend;

use backend::Backend;
use rpassword::read_password;
use std::env;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendType {
    #[cfg(feature = "secret-service-backend")]
    SecretService,
    #[cfg(feature = "age-backend")]
    Age,
}

impl BackendType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "secret-service-backend")]
            "secret-service" | "secretservice" | "dbus" => Some(Self::SecretService),
            #[cfg(feature = "age-backend")]
            "age" | "file" => Some(Self::Age),
            _ => None,
        }
    }

    fn default() -> Self {
        // Prefer secret-service if available, fallback to age
        #[cfg(feature = "secret-service-backend")]
        {
            Self::SecretService
        }
        #[cfg(all(not(feature = "secret-service-backend"), feature = "age-backend"))]
        {
            Self::Age
        }
    }
}

fn create_backend(
    backend_type: BackendType,
    #[allow(unused_variables)] age_identity: Option<PathBuf>,
) -> Result<Box<dyn Backend>, String> {
    match backend_type {
        #[cfg(feature = "secret-service-backend")]
        BackendType::SecretService => {
            Ok(Box::new(backend::secret_service::SecretServiceBackend::new()?))
        }
        #[cfg(feature = "age-backend")]
        BackendType::Age => Ok(Box::new(backend::age::AgeBackend::new(age_identity)?)),
    }
}

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

Backend options:
  --backend <type>       Backend type: 'secret-service' (default) or 'age'
  --age-identity <path>  Path to age identity file (SSH key or age identity)
                         Can also be set via ENVCHAIN_AGE_IDENTITY env var

Environment variables:
  ENVCHAIN_BACKEND       Default backend ('secret-service' or 'age')
  ENVCHAIN_AGE_IDENTITY  Path to age identity file for age backend
"
    );
}

fn list_namespaces(backend: &dyn Backend) -> Result<(), String> {
    let namespaces = backend.list_namespaces()?;
    for ns in namespaces {
        println!("{ns}");
    }
    Ok(())
}

fn list_values(backend: &dyn Backend, target: &str, show_value: bool) -> Result<(), String> {
    let secrets = backend.list_secrets(target)?;
    if secrets.is_empty() {
        eprintln!(
            "WARNING: namespace `{}` not defined.\n         You can set via running `{} --set {} SOME_ENV_NAME`.\n",
            target,
            env::args().next().unwrap_or_else(|| "envchain".into()),
            target
        );
        return Ok(());
    }
    let mut keys: Vec<_> = secrets.keys().collect();
    keys.sort();
    for key in keys {
        if show_value {
            println!("{}={}", key, secrets.get(key).unwrap());
        } else {
            println!("{key}");
        }
    }
    Ok(())
}

fn set_values(backend: &mut dyn Backend, noecho: bool, name: &str, keys: &[String]) -> Result<(), String> {
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
        backend.set_secret(name, key, &value)?;
    }
    Ok(())
}

fn unset_values(backend: &mut dyn Backend, name: &str, keys: &[String]) -> Result<(), String> {
    for key in keys {
        backend.delete_secret(name, key)?;
    }
    Ok(())
}

fn exec_with(backend: &dyn Backend, name_csv: &str, cmd: &str, args: &[String]) -> Result<(), String> {
    for name in name_csv.split(',') {
        let secrets = backend.list_secrets(name)?;
        for (key, val) in secrets {
            // SAFETY: We are the only thread running at this point before exec,
            // and we're about to replace this process with exec anyway.
            unsafe { env::set_var(&key, val) };
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

    // Parse global options first
    let mut backend_type = env::var("ENVCHAIN_BACKEND")
        .ok()
        .and_then(|s| BackendType::from_str(&s))
        .unwrap_or_else(BackendType::default);
    let mut age_identity: Option<PathBuf> = None;

    // Extract global options
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help(&prog);
                std::process::exit(0);
            }
            "--backend" => {
                args.remove(i);
                if i >= args.len() {
                    eprintln!("--backend requires an argument");
                    std::process::exit(2);
                }
                let backend_str = args.remove(i);
                backend_type = BackendType::from_str(&backend_str).unwrap_or_else(|| {
                    eprintln!("Unknown backend: {backend_str}");
                    eprintln!("Available: secret-service, age");
                    std::process::exit(2);
                });
            }
            "--age-identity" => {
                args.remove(i);
                if i >= args.len() {
                    eprintln!("--age-identity requires an argument");
                    std::process::exit(2);
                }
                age_identity = Some(PathBuf::from(args.remove(i)));
            }
            _ => i += 1,
        }
    }

    if args.is_empty() {
        print_help(&prog);
        std::process::exit(2);
    }

    // Create backend
    let mut backend = match create_backend(backend_type, age_identity) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

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
            if let Err(e) = set_values(backend.as_mut(), noecho, &name, &args) {
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
                list_values(backend.as_ref(), &t, show_value)
            } else if show_value {
                print_help(&prog);
                std::process::exit(2);
            } else {
                list_namespaces(backend.as_ref())
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
            if let Err(e) = unset_values(backend.as_mut(), &name, &args) {
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
            if let Err(e) = exec_with(backend.as_ref(), &name_csv, &cmd, &args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}
