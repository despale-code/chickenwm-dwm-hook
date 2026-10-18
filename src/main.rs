//! Phase 1.1: `chickenwm-dwm-hook` CLI & Manager for PDB Symbol Resolution,
//! DWM DLL Injection, and Safe Unhook/Ejection.

use anyhow::Result;
use clap::Parser;
use chickenwm_core::bootstrap_config_and_themes;
use chickenwm_core::init_tracing;
use chickenwm_dwm_hook::{
    eject_from_dwm, extract_pe_pdb_signature, inject_into_dwm, is_dwm_hook_injected, ping_dwm_ipc,
    resolve_system_dwm_offsets,
};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(
    name = "chickenwm-dwm-hook",
    version,
    about = "ChickenWM Experimental DWM PDB Resolver & Composition Hook Manager"
)]
struct Cli {
    /// Inspect PE CodeView RSDS signatures and optionally download Microsoft PDB symbols for `uDWM.dll` and `dwmcore.dll`.
    #[arg(long)]
    resolve_pdb: bool,

    /// Download missing `.pdb` symbol files from Microsoft Symbol Server when `--resolve-pdb` is used.
    #[arg(long)]
    download_symbols: bool,

    /// Inject `chickenwm_dwm_hook.dll` into `dwm.exe` (requires Administrator and Anti-Cheat Safe Switch enabled).
    #[arg(long)]
    inject: bool,

    /// Eject `chickenwm_dwm_hook.dll` from `dwm.exe` and restore original DWM composition bytes.
    #[arg(long)]
    eject: bool,

    /// Check whether `chickenwm_dwm_hook.dll` is injected into `dwm.exe` and answering on `\\.\pipe\dwm_ipc`.
    #[arg(long)]
    status: bool,
}

fn main() -> Result<()> {
    init_tracing("chickenwm_dwm_hook");
    let cli = Cli::parse();

    if cli.status {
        let injected = is_dwm_hook_injected();
        if let Some((hooks, visuals)) = ping_dwm_ipc() {
            println!("active: injected={injected} hooks={hooks} tracked_visuals={visuals}");
        } else if injected {
            println!("injected: module loaded in dwm.exe (pipe idle)");
        } else {
            println!("inactive");
            std::process::exit(1);
        }
        return Ok(());
    }

    if cli.eject {
        eject_from_dwm()?;
        println!("ok: Ejected chickenwm_dwm_hook.dll from dwm.exe and restored DWM composition.");
        return Ok(());
    }

    if cli.resolve_pdb {
        let offsets = resolve_system_dwm_offsets(cli.download_symbols)?;
        println!("{}", serde_json::to_string_pretty(&offsets)?);
        return Ok(());
    }

    if cli.inject {
        let (_doc, cfg) = bootstrap_config_and_themes()?;
        if !cfg.misc.dwm_hook_enabled {
            eprintln!(
                "Anti-Cheat Safe Switch is active (misc:dwm_hook_enabled = false). Enable it in chickenwm-settings or chickenwm.conf before injecting."
            );
            std::process::exit(1);
        }
        let mut dll_path = std::env::current_exe()?;
        dll_path.set_file_name("chickenwm_dwm_hook.dll");
        inject_into_dwm(&dll_path)?;
        println!("ok: Injected {}", dll_path.display());
        return Ok(());
    }

    // Default diagnostic output: print PE PDB signatures for system uDWM.dll & dwmcore.dll
    for sys_dll in [
        r"C:\Windows\System32\uDWM.dll",
        r"C:\Windows\System32\dwmcore.dll",
    ] {
        let p = Path::new(sys_dll);
        if p.exists() {
            match extract_pe_pdb_signature(p) {
                Ok(sig) => {
                    println!(
                        "{}: PDB={} GUID+Age={} URL={}",
                        sig.dll_name,
                        sig.pdb_name,
                        sig.guid_age_hex,
                        sig.symbol_server_url()
                    );
                }
                Err(e) => eprintln!("Failed to read signature for {}: {}", sys_dll, e),
            }
        }
    }

    Ok(())
}
