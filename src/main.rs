mod agent;
mod config;
mod log;
mod policy;

use std::path::Path;
use std::process::ExitCode;

const CREDENTIAL_NAME: &str = "vault-unseal-share";
pub const VERSION: &str = match option_env!("VSU_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("vault-share-unsealer {}", VERSION);
        return ExitCode::SUCCESS;
    }
    let [_, config_path] = args.as_slice() else {
        log_error!("usage: vault-share-unsealer <config.toml>");
        return ExitCode::from(2);
    };
    let config = match config::Config::load(Path::new(config_path)) {
        Ok(config) => config,
        Err(e) => {
            log_error!("config {config_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let share = match agent::Share::from_credentials(
        std::env::var_os("CREDENTIALS_DIRECTORY"),
        CREDENTIAL_NAME,
    ) {
        Ok(share) => share,
        Err(e) => {
            log_error!("credential {CREDENTIAL_NAME}: {e}");
            return ExitCode::from(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log_error!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(agent::run(config, share)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log_error!("{e}");
            ExitCode::from(1)
        }
    }
}
