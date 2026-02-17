mod backend;

use backend::Backend;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
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
    #[cfg(feature = "windows-credential-manager")]
    WindowsCredentialManager,
}

impl BackendType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "secret-service-backend")]
            "secret-service" | "secretservice" | "dbus" => Some(Self::SecretService),
            #[cfg(feature = "age-backend")]
            "age" | "file" => Some(Self::Age),
            #[cfg(feature = "windows-credential-manager")]
            "wincred" | "windows-credential-manager" | "windows" => {
                Some(Self::WindowsCredentialManager)
            }
            _ => None,
        }
    }

    fn default() -> Self {
        // Prefer secret-service if available, fallback to age
        #[cfg(feature = "secret-service-backend")]
        {
            Self::SecretService
        }
        #[cfg(all(
            not(feature = "secret-service-backend"),
            feature = "windows-credential-manager"
        ))]
        {
            Self::WindowsCredentialManager
        }
        #[cfg(all(
            not(feature = "secret-service-backend"),
            not(feature = "windows-credential-manager"),
            feature = "age-backend"
        ))]
        {
            Self::Age
        }
    }
}

#[derive(Parser)]
#[command(name = "envchain")]
#[command(version)]
#[command(about = "Environment variables meet secret storage")]
#[command(long_about = None)]
struct Cli {
    /// Backend type: 'secret-service', 'age', or 'wincred'
    #[arg(long, global = true, value_name = "TYPE")]
    backend: Option<String>,

    /// Path to age identity file
    #[arg(long, global = true, value_name = "PATH")]
    age_identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Namespace or comma-separated namespaces (for exec mode)
    #[arg(value_name = "NAMESPACE")]
    namespace: Option<String>,
    
    /// Command to execute (for exec mode)
    #[arg(value_name = "COMMAND", requires = "namespace")]
    exec_command: Option<String>,
    
    /// Arguments for the command (for exec mode)
    #[arg(value_name = "ARGS", requires = "exec_command", trailing_var_arg = true, allow_hyphen_values = true)]
    exec_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set environment variables in a namespace
    Set {
        /// Namespace to store variables in
        namespace: String,
        
        /// Environment variable names to set
        #[arg(required = true)]
        vars: Vec<String>,
        
        /// Do not echo user input
        #[arg(short, long)]
        noecho: bool,
    },
    
    /// List namespaces or variables
    List {
        /// Namespace to list variables from (lists all namespaces if omitted)
        namespace: Option<String>,
        
        /// Show values when listing
        #[arg(short = 'v', long)]
        show_value: bool,
    },
    
    /// Remove variables from a namespace
    Unset {
        /// Namespace to remove variables from
        namespace: String,
        
        /// Environment variable names to remove
        #[arg(required = true)]
        vars: Vec<String>,
    },
    
    /// Generate shell completion script
    GetCompletions {
        /// Shell type
        #[arg(value_enum)]
        shell: Shell,
    },
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
        #[cfg(feature = "windows-credential-manager")]
        BackendType::WindowsCredentialManager => Ok(Box::new(
            backend::windows_credential_manager::WindowsCredentialManagerBackend::new()?,
        )),
    }
}

fn print_completions(shell: Shell, cmd: &mut clap::Command) {
    clap_complete::generate(shell, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
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
    let mut keys: Vec<String> = Vec::new();
    for name in name_csv.split(',') {
        let secrets = backend.list_secrets(name)?;
        for (key, val) in secrets {
            // SAFETY: We are the only thread running at this point before exec,
            // and we're about to replace this process with exec anyway.
            unsafe { env::set_var(&key, &val) };
            keys.push(key);
        }
    }

    // On Windows, append secret keys to WSLENV so they are forwarded
    // across the WSL interop boundary when the child process is a WSL command.
    #[cfg(target_os = "windows")]
    if !keys.is_empty() {
        let mut wslenv = env::var("WSLENV").unwrap_or_default();
        for key in &keys {
            if !wslenv.is_empty() {
                wslenv.push(':');
            }
            wslenv.push_str(key);
        }
        unsafe { env::set_var("WSLENV", &wslenv) };
    }

    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| format!("exec failed: {e}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn main() {
    let cli = Cli::parse();

    // Handle get-completions subcommand first
    if let Some(command) = &cli.command {
        match command {
            Commands::GetCompletions { shell } => {
                let mut cmd = Cli::command();
                print_completions(*shell, &mut cmd);
                return;
            }
            Commands::Set { namespace, vars, noecho } => {
                let (backend_type, age_identity) = parse_backend_options(&cli);
                let mut backend = create_backend_or_exit(backend_type, age_identity);
                
                if let Err(e) = set_values(backend.as_mut(), *noecho, namespace, vars) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return;
            }
            Commands::List { namespace, show_value } => {
                let (backend_type, age_identity) = parse_backend_options(&cli);
                let backend = create_backend_or_exit(backend_type, age_identity);
                
                let res = if let Some(ns) = namespace {
                    list_values(backend.as_ref(), ns, *show_value)
                } else {
                    list_namespaces(backend.as_ref())
                };
                
                if let Err(e) = res {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return;
            }
            Commands::Unset { namespace, vars } => {
                let (backend_type, age_identity) = parse_backend_options(&cli);
                let mut backend = create_backend_or_exit(backend_type, age_identity);
                
                if let Err(e) = unset_values(backend.as_mut(), namespace, vars) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return;
            }
        }
    }

    // Default exec mode: envchain NAMESPACE COMMAND [ARGS...]
    if let (Some(namespace), Some(command)) = (&cli.namespace, &cli.exec_command) {
        let (backend_type, age_identity) = parse_backend_options(&cli);
        let backend = create_backend_or_exit(backend_type, age_identity);
        
        if let Err(e) = exec_with(backend.as_ref(), namespace, command, &cli.exec_args) {
            eprintln!("{e}");
            std::process::exit(1);
        }
    } else {
        // No valid subcommand or exec mode - show help
        eprintln!("Error: Missing subcommand or execution arguments\n");
        Cli::command().print_help().ok();
        std::process::exit(2);
    }
}

fn parse_backend_options(cli: &Cli) -> (BackendType, Option<PathBuf>) {
    let backend_env = env::var("ENVCHAIN_BACKEND").ok();
    let backend_str = cli.backend.as_deref().or_else(|| backend_env.as_deref());
    let backend_type = backend_str
        .and_then(BackendType::from_str)
        .unwrap_or_else(BackendType::default);
    
    (backend_type, cli.age_identity.clone())
}

fn create_backend_or_exit(backend_type: BackendType, age_identity: Option<PathBuf>) -> Box<dyn Backend> {
    match create_backend(backend_type, age_identity) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
