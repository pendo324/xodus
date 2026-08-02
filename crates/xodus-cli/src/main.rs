use std::process::ExitCode;

use clap::{Parser, Subcommand};
use xodus::tokens::TokenManager;

mod appx;
mod commands;
mod license;
mod package;
mod webview;

#[derive(Subcommand)]
enum SubCommand {
    #[command(about = "Download msixvc or xsp files fo given game")]
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Display download URLs instead of downloading"
        )]
        dry_run: bool,
    },
    #[command(about = "Dump CIKs for use with XvdTool")]
    License {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Extract locally stored msixvc file")]
    Extract {
        path: String,
        destination: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Fully decrypt every file, including ones normally left encrypted \
                    (e.g. the main .exe) for the wine-mount pipeline"
        )]
        decrypt_all: bool,
    },
    Login,
    Logout {
        #[arg(long, default_value_t = false, help = "Remove device license")]
        device: bool,
    },
    #[command(about = "List the signed-in account's entitled titles, including Game Pass")]
    Library {
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Download and extract the game through streaming algorithm")]
    Streaming {
        source: String,
        destination: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Attempt to skip downloading NTFS metadata to be faste while missing some files"
        )]
        try_skip_ntfs: bool,
        #[arg(short, long)]
        parallel: Option<usize>,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Fully decrypt every file, including ones normally left encrypted \
                    (e.g. the main .exe) for the wine-mount pipeline"
        )]
        decrypt_all: bool,
    },
    #[cfg(unix)]
    #[command(about = "Run a Game with xodus wine")]
    Run {
        source: String,
        wine: String,
        #[arg(short, long)]
        exe: Option<String>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[cfg(unix)]
    #[command(
        about = "Verify: run a GDK title through umu-run with a locally built xgameruntime.dll \
                 substituted in, downloading and extracting it first if it isn't already \
                 present as plain files on disk"
    )]
    RunUmu {
        #[clap(
            help = "Either a directory containing the extracted, plain (unencrypted) title \
                    files, or a product/content id to download and extract automatically \
                    (cached under $XDG_DATA_HOME/xodus/titles/<id>)"
        )]
        game: String,
        #[clap(
            long,
            help = "Path to the title's .exe, relative to the game directory (auto-detected \
                    if there's exactly one .exe under it)"
        )]
        exe: Option<String>,
        #[clap(help = "Path to the locally built xgameruntime.dll")]
        xgameruntime_dll: String,
        #[arg(
            long,
            help = "WINEPREFIX to use/create (default: $XDG_DATA_HOME/xodus/umu-verify-prefix)"
        )]
        prefix: Option<String>,
        #[arg(long, help = "PROTONPATH to pass through to umu-run")]
        proton: Option<String>,
        #[arg(long, help = "GAMEID to pass through to umu-run")]
        gameid: Option<String>,
        #[arg(
            short,
            long,
            help = "Market to use when downloading (if `game` is a product id)"
        )]
        market: Option<String>,
    },
    #[command(about = "Generate or decrypt base64-encoded CLEP challenge data")]
    Clep {
        #[command(subcommand)]
        action: ClepAction,
    },
    #[command(about = "Decode SPLicenseBlock")]
    SpLicense {
        block: String,
    },
    #[command(about = "Prove possession of the stored proof key against Xbox Live device auth")]
    DeviceAuth,
}

#[derive(Subcommand)]
enum ClepAction {
    #[command(
        about = "Generate a base64-encoded CLEP challenge (V2 and V4) from SMBIOS/disk serial data"
    )]
    Generate {
        #[arg(
            long,
            help = "Base64-encoded SMBIOS data (up to 256 bytes, zero-padded)"
        )]
        smbios: Option<String>,
        #[arg(
            long,
            help = "Base64-encoded disk serial (up to 64 bytes, zero-padded)"
        )]
        disk_serial: Option<String>,
    },
    #[command(about = "Decrypt a base64-encoded CLEP challenge back into its plaintext fields")]
    Decrypt {
        #[clap(help = "Base64-encoded, obfuscated CLEP challenge data (2048 bytes)")]
        data: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: SubCommand,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init_from_env("XODUS_LOG");
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .connection_verbose(true)
        .build()
        .unwrap();
    let args = CliArgs::parse();

    xodus::secrets::init_secrets().expect("Unable to initialize credentials");
    let tokens = TokenManager::with_keychain_and_memory();
    xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;

    let code = match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, &tokens, product, market, dry_run).await,
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                &client,
                &tokens,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await
        }
        SubCommand::Login => commands::login::run(&client, &tokens).await,
        SubCommand::Logout { device } => commands::logout::run(&tokens, device).await,
        SubCommand::Library { market } => commands::library::run(&client, &tokens, market).await,
        SubCommand::Extract {
            path,
            destination,
            market,
            decrypt_all,
        } => {
            commands::extract::run(
                &client,
                &tokens,
                path,
                destination,
                market.unwrap_or("neutral".to_string()),
                decrypt_all,
            )
            .await
        }
        SubCommand::Streaming {
            source,
            destination,
            try_skip_ntfs,
            market,
            parallel,
            decrypt_all,
        } => {
            commands::streaming::run(
                &client,
                &tokens,
                source,
                destination,
                try_skip_ntfs,
                parallel,
                market,
                decrypt_all,
            )
            .await
        }
        #[cfg(unix)]
        SubCommand::Run {
            source,
            wine,
            exe,
            market,
        } => commands::run::run(&client, &tokens, source, wine, exe, market).await,
        #[cfg(unix)]
        SubCommand::RunUmu {
            game,
            exe,
            xgameruntime_dll,
            prefix,
            proton,
            gameid,
            market,
        } => {
            commands::run_umu::run(
                &client,
                &tokens,
                game,
                exe,
                xgameruntime_dll,
                prefix,
                proton,
                gameid,
                market,
            )
            .await
        }
        SubCommand::Clep { action } => match action {
            ClepAction::Generate {
                smbios,
                disk_serial,
            } => commands::clep::generate(smbios, disk_serial),
            ClepAction::Decrypt { data } => commands::clep::decrypt(data),
        },
        SubCommand::SpLicense { block } => commands::splicense::run(block),
        SubCommand::DeviceAuth => commands::deviceauth::run(&tokens).await,
    };

    xodus::secrets::destroy_secrets();

    code
}
