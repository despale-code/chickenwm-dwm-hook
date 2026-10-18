//! Phase 1.1: Experimental DWM DLL Injection (`chickenwm-dwm-hook`)
//! - Automated PE CodeView (`RSDS`) extractor & Microsoft PDB Symbol Server downloader (`uDWM.dll` / `dwmcore.dll`)
//! - `pdb` crate symbol offset resolver for `CTopLevelWindow`, `CDesktopManager`, and `CVisual`
//! - Safe x86_64 Trampoline / Detour hooking engine (`VirtualProtect` / `VirtualAlloc`)
//! - Direct 4x4 & 3x2 composition matrix manipulation (`Scale`, `Translate`, `Opacity`) and in-tree border shader state
//! - Anti-Cheat Safe Switch integration & clean DLL ejection on emergency failsafe (`Ctrl+Alt+Shift+Esc`)

use anyhow::{Context, Result};
use chickenwm_core::config::config_dir;
use chickenwm_core::failsafe::DWM_HOOK_ACTIVE;
use chickenwm_core::handles::SafeHandle;
use parking_lot::{Mutex, RwLock};
use pdb::FallibleIterator;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use tracing::{info, warn};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, HINSTANCE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenSessionId,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Diagnostics::Debug::{
    SymCleanup, SymFromNameW, SymInitializeW, SymLoadModuleExW, SymSetOptions, WriteProcessMemory,
    SYMBOL_INFOW, SYMOPT_DEFERRED_LOADS, SYMOPT_UNDNAME, SYM_LOAD_FLAGS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx, VirtualProtect, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Default Named Pipe endpoint exposed by `chickenwm_dwm_hook.dll` inside `dwm.exe`.
pub const PIPE_NAME_DWM_IPC: &str = r"\\.\pipe\dwm_ipc";

/// CodeView RSDS debug directory signature extracted from a PE binary (`uDWM.dll` or `dwmcore.dll`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PePdbSignature {
    pub dll_name: String,
    pub pdb_name: String,
    pub guid_age_hex: String,
}

impl PePdbSignature {
    /// Returns the official Microsoft Symbol Server download URL for this binary's PDB.
    pub fn symbol_server_url(&self) -> String {
        format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
            self.pdb_name, self.guid_age_hex, self.pdb_name
        )
    }
}

/// Resolved RVA (Relative Virtual Address) offsets inside `uDWM.dll` and `dwmcore.dll`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DwmResolvedOffsets {
    pub udwm_signature: Option<PePdbSignature>,
    pub dwmcore_signature: Option<PePdbSignature>,
    /// RVA of `CDesktopManager::s_pDesktopManagerInstance` in `uDWM.dll`
    pub rva_desktop_manager_instance: Option<u32>,
    /// RVA of `CTopLevelWindow::ValidateVisual` in `uDWM.dll`
    pub rva_top_level_validate_visual: Option<u32>,
    /// RVA of `CTopLevelWindow::UpdateWindowVisuals` in `uDWM.dll`
    pub rva_top_level_update_visuals: Option<u32>,
    /// RVA of `CTopLevelWindow::SetPosition` / `OnWindowSizeUpdated` in `uDWM.dll`
    #[serde(default)]
    pub rva_top_level_set_position: Option<u32>,
    /// RVA of `CVisual::SetScale` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_scale: Option<u32>,
    /// RVA of `CVisual::SetOffset` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_offset: Option<u32>,
    /// RVA of `CVisual::SetOpacity` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_opacity: Option<u32>,
    /// RVA of `CVisual::SetVisible` in `uDWM.dll` / `dwmcore.dll`
    #[serde(default)]
    pub rva_visual_set_visible: Option<u32>,
    /// RVA of `CComposition::PreRender` / `ProcessComposition` in `dwmcore.dll`
    pub rva_dwmcore_process_composition: Option<u32>,
    /// RVA of `CComposition::Present` in `dwmcore.dll`
    #[serde(default)]
    pub rva_composition_present: Option<u32>,
    /// Map of all matched DWM symbols to their RVAs.
    pub all_matched_rvas: HashMap<String, u32>,
}

/// Extracts the `RSDS` CodeView PDB GUID, Age, and PDB filename from a PE64 image on disk.
pub fn extract_pe_pdb_signature(pe_path: &Path) -> Result<PePdbSignature> {
    let bytes = std::fs::read(pe_path)
        .with_context(|| format!("Failed to read PE binary {}", pe_path.display()))?;

    let dll_name = pe_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown.dll")
        .to_string();

    // Scan for "RSDS" signature block `[b'R', b'S', b'D', b'S', guid(16 bytes), age(4 bytes), pdb_filename\0]`
    for i in 0..bytes.len().saturating_sub(32) {
        if &bytes[i..i + 4] == b"RSDS" {
            let guid_bytes = &bytes[i + 4..i + 20];
            let age = u32::from_le_bytes([
                bytes[i + 20],
                bytes[i + 21],
                bytes[i + 22],
                bytes[i + 23],
            ]);
            let name_start = i + 24;
            if let Some(null_rel) = bytes[name_start..]
                .iter()
                .take(260)
                .position(|&b| b == 0)
            {
                if null_rel >= 5 {
                    if let Ok(raw_name) = std::str::from_utf8(&bytes[name_start..name_start + null_rel])
                    {
                        if raw_name.to_ascii_lowercase().ends_with(".pdb") {
                            let pdb_file_name = Path::new(raw_name)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(raw_name)
                                .to_string();

                            let d1 = u32::from_le_bytes([
                                guid_bytes[0],
                                guid_bytes[1],
                                guid_bytes[2],
                                guid_bytes[3],
                            ]);
                            let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
                            let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
                            let d4 = &guid_bytes[8..16];

                            let guid_age_hex = format!(
                                "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                                d1,
                                d2,
                                d3,
                                d4[0],
                                d4[1],
                                d4[2],
                                d4[3],
                                d4[4],
                                d4[5],
                                d4[6],
                                d4[7],
                                age
                            );

                            return Ok(PePdbSignature {
                                dll_name,
                                pdb_name: pdb_file_name,
                                guid_age_hex,
                            });
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!(
        "Could not locate RSDS CodeView PDB record in {}",
        pe_path.display()
    )
}

/// Downloads the PDB file for `sig` from Microsoft's Symbol Server into `~/.config/chickenwm/symbols/`
/// if not already cached on disk.
pub fn download_pdb_if_needed(sig: &PePdbSignature) -> Result<PathBuf> {
    let sym_dir = config_dir().join("symbols").join(&sig.guid_age_hex);
    std::fs::create_dir_all(&sym_dir)?;
    let pdb_path = sym_dir.join(&sig.pdb_name);
    if pdb_path.exists() && pdb_path.metadata().map(|m| m.len() > 1024).unwrap_or(false) {
        return Ok(pdb_path);
    }

    let url = sig.symbol_server_url();
    info!(
        "Downloading Microsoft PDB symbols for {} from {}...",
        sig.dll_name, url
    );

    let status = Command::new("curl.exe")
        .args([
            "-s",
            "-L",
            "--fail",
            "--max-time",
            "30",
            "-o",
            &pdb_path.to_string_lossy(),
            &url,
        ])
        .status()
        .context("Failed to execute curl.exe for Microsoft PDB download")?;

    if !status.success() || !pdb_path.exists() {
        anyhow::bail!("PDB download from {} returned non-zero status", url);
    }

    Ok(pdb_path)
}

/// Parses a downloaded `.pdb` file using the `pdb` crate to resolve RVA offsets for
/// `CTopLevelWindow`, `CDesktopManager`, `CVisual`, and `CComposition`.
pub fn parse_pdb_offsets(pdb_path: &Path, offsets: &mut DwmResolvedOffsets) -> Result<()> {
    let file = File::open(pdb_path)
        .with_context(|| format!("Failed to open PDB file {}", pdb_path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("Failed to parse PDB container")?;

    let address_map = pdb.address_map().context("Failed to read PDB address map")?;
    let symbol_table = pdb.global_symbols().context("Failed to read PDB global symbols")?;
    let mut symbols = symbol_table.iter();

    while let Some(symbol) = symbols.next().context("Error iterating PDB symbols")? {
        if let Ok(pdb::SymbolData::Public(pub_sym)) = symbol.parse() {
            let name = pub_sym.name.to_string().into_owned();
            if let Some(rva) = pub_sym.offset.to_rva(&address_map) {
                let rva_val = rva.0;
                record_matched_symbol(&name, rva_val, offsets);
            }
        }
    }

    Ok(())
}

fn record_matched_symbol(name: &str, rva_val: u32, offsets: &mut DwmResolvedOffsets) {
    if name.contains("s_pDesktopManagerInstance") {
        offsets.rva_desktop_manager_instance = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CTopLevelWindow") && name.contains("ValidateVisual") {
        offsets.rva_top_level_validate_visual = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CTopLevelWindow") && name.contains("UpdateWindowVisuals") {
        offsets.rva_top_level_update_visuals = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CTopLevelWindow")
        && (name.contains("SetPosition") || name.contains("OnWindowSizeUpdated"))
    {
        offsets.rva_top_level_set_position = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CVisual") && name.contains("SetScale") {
        offsets.rva_visual_set_scale = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CVisual") && name.contains("SetOffset") {
        offsets.rva_visual_set_offset = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CVisual") && name.contains("SetOpacity") {
        offsets.rva_visual_set_opacity = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CVisual") && name.contains("SetVisible") {
        offsets.rva_visual_set_visible = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CComposition")
        && (name.contains("PreRender") || name.contains("ProcessComposition"))
    {
        offsets.rva_dwmcore_process_composition = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    } else if name.contains("CComposition") && name.contains("Present") {
        offsets.rva_composition_present = Some(rva_val);
        offsets.all_matched_rvas.insert(name.to_string(), rva_val);
    }
}

/// Phase 11.1: Resolves unexported internal RVAs via Win32 `DbgHelp` (`SymInitializeW` + `SymFromNameW`).
pub fn resolve_symbols_via_dbghelp(
    module_path: &Path,
    pdb_search_dir: Option<&Path>,
    offsets: &mut DwmResolvedOffsets,
) -> Result<()> {
    const FAKE_BASE: u64 = 0x1000_0000;
    unsafe {
        let proc = GetCurrentProcess();
        let _ = SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        let search_wide: Option<Vec<u16>> = pdb_search_dir.map(|p| {
            p.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect()
        });
        let search_pcwstr = search_wide
            .as_ref()
            .map(|w| PCWSTR(w.as_ptr()))
            .unwrap_or(PCWSTR::null());

        if SymInitializeW(proc, search_pcwstr, false).is_err() {
            return Ok(());
        }

        let mod_wide: Vec<u16> = module_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let loaded_base = SymLoadModuleExW(
            proc,
            HANDLE::default(),
            PCWSTR(mod_wide.as_ptr()),
            PCWSTR::null(),
            FAKE_BASE,
            0,
            None,
            SYM_LOAD_FLAGS(0),
        );
        if loaded_base != 0 {
            let candidates = [
                "CDesktopManager::s_pDesktopManagerInstance",
                "CTopLevelWindow::ValidateVisual",
                "CTopLevelWindow::UpdateWindowVisuals",
                "CTopLevelWindow::SetPosition",
                "CTopLevelWindow::OnWindowSizeUpdated",
                "CVisual::SetScale",
                "CVisual::SetOffset",
                "CVisual::SetOpacity",
                "CVisual::SetVisible",
                "CComposition::PreRender",
                "CComposition::ProcessComposition",
                "CComposition::Present",
            ];
            let mut buf = vec![0u8; std::mem::size_of::<SYMBOL_INFOW>() + 512];
            for sym_name in candidates {
                buf.fill(0);
                let info_ptr = buf.as_mut_ptr() as *mut SYMBOL_INFOW;
                (*info_ptr).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
                (*info_ptr).MaxNameLen = 255;
                let wide_sym: Vec<u16> = sym_name.encode_utf16().chain(std::iter::once(0)).collect();
                if SymFromNameW(proc, PCWSTR(wide_sym.as_ptr()), info_ptr).is_ok() {
                    let addr = (*info_ptr).Address;
                    if addr >= loaded_base {
                        let rva_val = (addr - loaded_base) as u32;
                        record_matched_symbol(sym_name, rva_val, offsets);
                    }
                }
            }
        }

        let _ = SymCleanup(proc);
    }
    Ok(())
}

/// Resolves `uDWM.dll` and `dwmcore.dll` offsets (downloading PDBs or loading from cache).
pub fn resolve_system_dwm_offsets(download_if_missing: bool) -> Result<DwmResolvedOffsets> {
    let cache_path = config_dir().join("symbols").join("dwm_offsets_cache.json");
    if !download_if_missing && cache_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&cache_path) {
            if let Ok(cached) = serde_json::from_str::<DwmResolvedOffsets>(&raw) {
                return Ok(cached);
            }
        }
    }

    let mut offsets = DwmResolvedOffsets::default();
    let udwm_path = Path::new(r"C:\Windows\System32\uDWM.dll");
    let dwmcore_path = Path::new(r"C:\Windows\System32\dwmcore.dll");

    if udwm_path.exists() {
        if let Ok(sig) = extract_pe_pdb_signature(udwm_path) {
            if download_if_missing {
                if let Ok(pdb_file) = download_pdb_if_needed(&sig) {
                    let _ = parse_pdb_offsets(&pdb_file, &mut offsets);
                    let _ = resolve_symbols_via_dbghelp(udwm_path, pdb_file.parent(), &mut offsets);
                }
            } else {
                let sym_dir = config_dir().join("symbols").join(&sig.guid_age_hex);
                let pdb_file = sym_dir.join(&sig.pdb_name);
                if pdb_file.exists() {
                    let _ = parse_pdb_offsets(&pdb_file, &mut offsets);
                    let _ = resolve_symbols_via_dbghelp(udwm_path, Some(&sym_dir), &mut offsets);
                }
            }
            offsets.udwm_signature = Some(sig);
        }
    }

    if dwmcore_path.exists() {
        if let Ok(sig) = extract_pe_pdb_signature(dwmcore_path) {
            if download_if_missing {
                if let Ok(pdb_file) = download_pdb_if_needed(&sig) {
                    let _ = parse_pdb_offsets(&pdb_file, &mut offsets);
                    let _ =
                        resolve_symbols_via_dbghelp(dwmcore_path, pdb_file.parent(), &mut offsets);
                }
            } else {
                let sym_dir = config_dir().join("symbols").join(&sig.guid_age_hex);
                let pdb_file = sym_dir.join(&sig.pdb_name);
                if pdb_file.exists() {
                    let _ = parse_pdb_offsets(&pdb_file, &mut offsets);
                    let _ =
                        resolve_symbols_via_dbghelp(dwmcore_path, Some(&sym_dir), &mut offsets);
                }
            }
            offsets.dwmcore_signature = Some(sig);
        }
    }

    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&offsets) {
        let _ = std::fs::write(&cache_path, &json);
        let shared_offsets = std::env::temp_dir().join("chickenwm_dwm_offsets.json");
        let _ = std::fs::write(shared_offsets, json);
    }

    Ok(offsets)
}

/// Phase 1.1: Direct Composition Matrix (`Scale`, `Translate`, `Opacity`) and Custom Shader/Border state
/// applied inside DWM's render tree.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DwmVisualTransform {
    pub hwnd: u64,
    pub scale_x: f32,
    pub scale_y: f32,
    pub translate_x: f32,
    pub translate_y: f32,
    pub opacity: f32,
    pub corner_radius: f32,
    pub border_rgba: [f32; 4],
    pub border_rgba_secondary: [f32; 4],
    pub border_angle_deg: f32,
    pub border_width: f32,
}

impl Default for DwmVisualTransform {
    fn default() -> Self {
        Self {
            hwnd: 0,
            scale_x: 1.0,
            scale_y: 1.0,
            translate_x: 0.0,
            translate_y: 0.0,
            opacity: 1.0,
            corner_radius: 10.0,
            border_rgba: [0.2, 0.8, 1.0, 0.93],
            border_rgba_secondary: [0.0, 1.0, 0.6, 0.93],
            border_angle_deg: 45.0,
            border_width: 2.0,
        }
    }
}

impl DwmVisualTransform {
    /// Builds a 4x4 DirectComposition affine transformation matrix (`Scale * Translate`).
    pub fn to_matrix_4x4(&self) -> [[f32; 4]; 4] {
        [
            [self.scale_x, 0.0, 0.0, 0.0],
            [0.0, self.scale_y, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [self.translate_x, self.translate_y, 0.0, 1.0],
        ]
    }

    /// Builds a 3x2 2D Direct2D/MilCore matrix (`[m11, m12, m21, m22, dx, dy]`).
    pub fn to_matrix_3x2(&self) -> [f32; 6] {
        [
            self.scale_x,
            0.0,
            0.0,
            self.scale_y,
            self.translate_x,
            self.translate_y,
        ]
    }
}

/// Safe x86_64 14-byte absolute jump (`FF 25 00 00 00 00 <u64>`) inline detour / trampoline hook.
pub struct TrampolineHook {
    target_addr: usize,
    trampoline_addr: usize,
    original_bytes: Vec<u8>,
    installed: bool,
}

impl TrampolineHook {
    const ABS_JMP_LEN: usize = 14;

    /// Installs an x86_64 trampoline detour from `target_addr` to `detour_fn`, preserving `prologue_len` (>= 14) bytes.
    pub unsafe fn install(
        target_addr: usize,
        detour_fn: usize,
        prologue_len: usize,
    ) -> Result<Self> {
        unsafe {
            let len = prologue_len.max(Self::ABS_JMP_LEN);
            let tramp_ptr = VirtualAlloc(
                None,
                len + Self::ABS_JMP_LEN,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if tramp_ptr.is_null() {
                anyhow::bail!("VirtualAlloc failed for trampoline buffer");
            }

            let target_slice = std::slice::from_raw_parts(target_addr as *const u8, len);
            let original_bytes = target_slice.to_vec();

            // Copy original prologue into trampoline, followed by 14-byte jump to target_addr + len
            let tramp_slice =
                std::slice::from_raw_parts_mut(tramp_ptr as *mut u8, len + Self::ABS_JMP_LEN);
            tramp_slice[..len].copy_from_slice(&original_bytes);
            Self::write_abs_jmp(
                &mut tramp_slice[len..len + Self::ABS_JMP_LEN],
                (target_addr + len) as u64,
            );

            // Patch target function entry point under VirtualProtect
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                target_addr as *const core::ffi::c_void,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )?;

            let target_mut = std::slice::from_raw_parts_mut(target_addr as *mut u8, len);
            Self::write_abs_jmp(&mut target_mut[..Self::ABS_JMP_LEN], detour_fn as u64);
            for b in &mut target_mut[Self::ABS_JMP_LEN..len] {
                *b = 0x90; // NOP padding
            }

            let _ = VirtualProtect(
                target_addr as *const core::ffi::c_void,
                len,
                old_protect,
                &mut old_protect,
            );

            Ok(Self {
                target_addr,
                trampoline_addr: tramp_ptr as usize,
                original_bytes,
                installed: true,
            })
        }
    }

    pub fn trampoline_fn_ptr(&self) -> usize {
        self.trampoline_addr
    }

    /// Restores the original bytes at `target_addr` and frees the trampoline buffer.
    pub unsafe fn unhook(&mut self) {
        if !self.installed {
            return;
        }
        unsafe {
            let len = self.original_bytes.len();
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            if VirtualProtect(
                self.target_addr as *const core::ffi::c_void,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .is_ok()
            {
                let target_mut = std::slice::from_raw_parts_mut(self.target_addr as *mut u8, len);
                target_mut.copy_from_slice(&self.original_bytes);
                let _ = VirtualProtect(
                    self.target_addr as *const core::ffi::c_void,
                    len,
                    old_protect,
                    &mut old_protect,
                );
            }
            let _ = VirtualFree(
                self.trampoline_addr as *mut core::ffi::c_void,
                0,
                MEM_RELEASE,
            );
        }
        self.installed = false;
    }

    fn write_abs_jmp(buf: &mut [u8], dest: u64) {
        buf[0] = 0xFF;
        buf[1] = 0x25;
        buf[2] = 0x00;
        buf[3] = 0x00;
        buf[4] = 0x00;
        buf[5] = 0x00;
        buf[6..14].copy_from_slice(&dest.to_le_bytes());
    }
}

impl Drop for TrampolineHook {
    fn drop(&mut self) {
        unsafe {
            self.unhook();
        }
    }
}

/// Phase 11.3: Scene-graph event kind emitted from `dwm.exe` to the Window Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DwmEventKind {
    WindowCreated,
    WindowDestroyed,
    TransformChanged,
    ZOrderUpdated,
}

/// Phase 11.3: Outbound telemetry event streamed from `chickenwm_dwm_hook.dll` inside `dwm.exe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DwmTelemetryEvent {
    pub kind: DwmEventKind,
    pub hwnd: u64,
    pub visual_node_id: u64,
    pub rect: [i32; 4],
    pub alpha: f32,
    pub shared_handle: u64,
}

/// Phase 11.3: Inbound layout/composition command sent from the Window Manager to `dwm.exe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DwmIpcCommand {
    /// `SET_POSITION(NodeID, X, Y, W, H)`
    SetPosition {
        node_id: u64,
        hwnd: u64,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
    },
    /// `SET_OPACITY(NodeID, Alpha)`
    SetOpacity {
        node_id: u64,
        hwnd: u64,
        alpha: f32,
    },
    /// `SUPPRESS_RENDER(NodeID, Bool)` — workspace virtualization without `SW_HIDE`.
    SuppressRender {
        node_id: u64,
        hwnd: u64,
        suppress: bool,
    },
    /// Update a single window's composition transform & shader state.
    UpdateTransform(DwmVisualTransform),
    /// Atomic batch update of window composition transforms for the current frame.
    UpdateTransformBatch(Vec<DwmVisualTransform>),
    /// Drain queued outbound scene-graph telemetry events from `dwm.exe`.
    DrainTelemetry,
    /// Liveness & hook status probe.
    Ping,
    /// Unhook all `dwmcore.dll` / `uDWM.dll` detours and stop the IPC server prior to `FreeLibrary`.
    Eject,
}

/// Response returned by `\\.\pipe\dwm_ipc`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DwmIpcResponse {
    Ack,
    Pong {
        hooked_functions: usize,
        tracked_visuals: usize,
    },
    Telemetry(Vec<DwmTelemetryEvent>),
    Error(String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DwmNodeOverride {
    pub node_id: u64,
    pub hwnd: u64,
    pub rect: Option<[i32; 4]>,
    pub opacity: Option<f32>,
    pub suppress_render: bool,
}

/// Global in-process transform registry used when `chickenwm_dwm_hook.dll` is loaded inside `dwm.exe`.
static VISUAL_TRANSFORMS: OnceLock<RwLock<HashMap<u64, DwmVisualTransform>>> = OnceLock::new();
static NODE_OVERRIDES: OnceLock<RwLock<HashMap<u64, DwmNodeOverride>>> = OnceLock::new();
static TELEMETRY_QUEUE: OnceLock<Mutex<VecDeque<DwmTelemetryEvent>>> = OnceLock::new();
static INSTALLED_HOOKS: OnceLock<Mutex<Vec<TrampolineHook>>> = OnceLock::new();
static HOOKED_FN_COUNT: AtomicUsize = AtomicUsize::new(0);
static UNHOOK_REQUESTED: AtomicBool = AtomicBool::new(false);
static PRE_RENDER_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static VALIDATE_VISUAL_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static FN_VISUAL_SET_OFFSET: AtomicUsize = AtomicUsize::new(0);
static FN_VISUAL_SET_SCALE: AtomicUsize = AtomicUsize::new(0);
static FN_VISUAL_SET_OPACITY: AtomicUsize = AtomicUsize::new(0);
static FN_VISUAL_SET_VISIBLE: AtomicUsize = AtomicUsize::new(0);

// Safety: `TrampolineHook` only holds raw addresses and a byte vector managed under `INSTALLED_HOOKS`.
unsafe impl Send for TrampolineHook {}

pub fn visual_transforms() -> &'static RwLock<HashMap<u64, DwmVisualTransform>> {
    VISUAL_TRANSFORMS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn node_overrides() -> &'static RwLock<HashMap<u64, DwmNodeOverride>> {
    NODE_OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn telemetry_queue() -> &'static Mutex<VecDeque<DwmTelemetryEvent>> {
    TELEMETRY_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(128)))
}

fn installed_hooks() -> &'static Mutex<Vec<TrampolineHook>> {
    INSTALLED_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Enqueues an outbound scene-graph telemetry event (capped at 256 entries to bound memory).
pub fn push_dwm_telemetry(event: DwmTelemetryEvent) {
    let mut q = telemetry_queue().lock();
    if q.len() >= 256 {
        q.pop_front();
    }
    q.push_back(event);
}

/// Updates the DWM visual transform for `hwnd` and forwards it over `\\.\pipe\dwm_ipc` when connected.
pub fn update_dwm_visual_transform(transform: DwmVisualTransform) {
    visual_transforms().write().insert(transform.hwnd, transform);
    let _ = send_dwm_ipc_command(&DwmIpcCommand::UpdateTransform(transform));
}

/// Sends an atomic batch of visual transforms to `\\.\pipe\dwm_ipc` (returns `true` if `dwm.exe` acknowledged).
pub fn update_dwm_visual_transforms_batch(transforms: &[DwmVisualTransform]) -> bool {
    {
        let mut map = visual_transforms().write();
        for &t in transforms {
            map.insert(t.hwnd, t);
        }
    }
    if transforms.is_empty() {
        return false;
    }
    matches!(
        send_dwm_ipc_command(&DwmIpcCommand::UpdateTransformBatch(transforms.to_vec())),
        Ok(DwmIpcResponse::Ack)
    )
}

/// Sends `SET_POSITION(NodeID, X, Y, W, H)` to `\\.\pipe\dwm_ipc`.
pub fn set_dwm_node_position(node_id: u64, hwnd: u64, x: i32, y: i32, w: i32, h: i32) -> bool {
    matches!(
        send_dwm_ipc_command(&DwmIpcCommand::SetPosition {
            node_id,
            hwnd,
            x,
            y,
            w,
            h,
        }),
        Ok(DwmIpcResponse::Ack)
    )
}

/// Sends `SET_OPACITY(NodeID, Alpha)` to `\\.\pipe\dwm_ipc`.
pub fn set_dwm_node_opacity(node_id: u64, hwnd: u64, alpha: f32) -> bool {
    matches!(
        send_dwm_ipc_command(&DwmIpcCommand::SetOpacity {
            node_id,
            hwnd,
            alpha,
        }),
        Ok(DwmIpcResponse::Ack)
    )
}

/// Sends `SUPPRESS_RENDER(NodeID, Bool)` to `\\.\pipe\dwm_ipc` (workspace virtualization without `SW_HIDE`).
pub fn set_dwm_node_suppress_render(node_id: u64, hwnd: u64, suppress: bool) -> bool {
    matches!(
        send_dwm_ipc_command(&DwmIpcCommand::SuppressRender {
            node_id,
            hwnd,
            suppress,
        }),
        Ok(DwmIpcResponse::Ack)
    )
}

/// Drains pending scene-graph telemetry events from `\\.\pipe\dwm_ipc`.
pub fn poll_dwm_telemetry() -> Vec<DwmTelemetryEvent> {
    match send_dwm_ipc_command(&DwmIpcCommand::DrainTelemetry) {
        Ok(DwmIpcResponse::Telemetry(events)) => events,
        _ => Vec::new(),
    }
}

/// Probes `\\.\pipe\dwm_ipc` and returns `Some((hooked_functions, tracked_visuals))` if active.
pub fn ping_dwm_ipc() -> Option<(usize, usize)> {
    match send_dwm_ipc_command(&DwmIpcCommand::Ping) {
        Ok(DwmIpcResponse::Pong {
            hooked_functions,
            tracked_visuals,
        }) => Some((hooked_functions, tracked_visuals)),
        _ => None,
    }
}

/// Sends a single command to `\\.\pipe\dwm_ipc` with a short non-blocking timeout.
pub fn send_dwm_ipc_command(cmd: &DwmIpcCommand) -> Result<DwmIpcResponse> {
    send_dwm_ipc_command_to(PIPE_NAME_DWM_IPC, cmd)
}

/// Sends a single command to a specified Named Pipe path and parses the JSON response.
pub fn send_dwm_ipc_command_to(pipe_name: &str, cmd: &DwmIpcCommand) -> Result<DwmIpcResponse> {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(80);
    let mut file = loop {
        unsafe {
            let _ = WaitNamedPipeW(PCWSTR(wide.as_ptr()), 20);
        }
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(f) => break f,
            Err(e) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(2));
                let _ = e;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to connect to {pipe_name}"));
            }
        }
    };

    let mut payload = serde_json::to_string(cmd)?;
    payload.push('\n');
    file.write_all(payload.as_bytes())?;
    file.flush()?;

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: DwmIpcResponse =
        serde_json::from_str(line.trim()).context("Invalid DwmIpcResponse JSON")?;
    Ok(resp)
}

fn handle_dwm_ipc_command(cmd: DwmIpcCommand) -> DwmIpcResponse {
    match cmd {
        DwmIpcCommand::SetPosition {
            node_id,
            hwnd,
            x,
            y,
            w,
            h,
        } => {
            let key = if node_id != 0 { node_id } else { hwnd };
            let mut map = node_overrides().write();
            let entry = map.entry(key).or_insert_with(|| DwmNodeOverride {
                node_id,
                hwnd,
                ..Default::default()
            });
            entry.rect = Some([x, y, w, h]);
            push_dwm_telemetry(DwmTelemetryEvent {
                kind: DwmEventKind::TransformChanged,
                hwnd,
                visual_node_id: node_id,
                rect: [x, y, w, h],
                alpha: entry.opacity.unwrap_or(1.0),
                shared_handle: 0,
            });
            DwmIpcResponse::Ack
        }
        DwmIpcCommand::SetOpacity {
            node_id,
            hwnd,
            alpha,
        } => {
            let key = if node_id != 0 { node_id } else { hwnd };
            let mut map = node_overrides().write();
            let entry = map.entry(key).or_insert_with(|| DwmNodeOverride {
                node_id,
                hwnd,
                ..Default::default()
            });
            entry.opacity = Some(alpha.clamp(0.0, 1.0));
            DwmIpcResponse::Ack
        }
        DwmIpcCommand::SuppressRender {
            node_id,
            hwnd,
            suppress,
        } => {
            let key = if node_id != 0 { node_id } else { hwnd };
            let mut map = node_overrides().write();
            let entry = map.entry(key).or_insert_with(|| DwmNodeOverride {
                node_id,
                hwnd,
                ..Default::default()
            });
            entry.suppress_render = suppress;
            DwmIpcResponse::Ack
        }
        DwmIpcCommand::UpdateTransform(t) => {
            visual_transforms().write().insert(t.hwnd, t);
            DwmIpcResponse::Ack
        }
        DwmIpcCommand::UpdateTransformBatch(batch) => {
            let mut map = visual_transforms().write();
            for t in batch {
                map.insert(t.hwnd, t);
            }
            DwmIpcResponse::Ack
        }
        DwmIpcCommand::DrainTelemetry => {
            let mut q = telemetry_queue().lock();
            let drained: Vec<DwmTelemetryEvent> = q.drain(..).collect();
            DwmIpcResponse::Telemetry(drained)
        }
        DwmIpcCommand::Ping => DwmIpcResponse::Pong {
            hooked_functions: HOOKED_FN_COUNT.load(Ordering::Relaxed),
            tracked_visuals: visual_transforms().read().len() + node_overrides().read().len(),
        },
        DwmIpcCommand::Eject => {
            UNHOOK_REQUESTED.store(true, Ordering::SeqCst);
            uninstall_dwmcore_hooks();
            DwmIpcResponse::Ack
        }
    }
}

/// Runs the Named Pipe IPC server loop on `pipe_name` until `stop_flag` or `DwmIpcCommand::Eject` triggers.
pub fn run_dwm_ipc_pipe_server(pipe_name: &str, stop_flag: &AtomicBool) {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let signal_path = std::env::temp_dir().join("chickenwm_dwm_unhook.signal");
    let _ = std::fs::remove_file(&signal_path);

    while !stop_flag.load(Ordering::SeqCst)
        && !UNHOOK_REQUESTED.load(Ordering::SeqCst)
        && !signal_path.exists()
    {
        unsafe {
            let pipe = CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                100,
                None,
            );
            if pipe.is_invalid() {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }

            let connected = ConnectNamedPipe(pipe, None).is_ok()
                || windows::Win32::Foundation::GetLastError()
                    == windows::Win32::Foundation::ERROR_PIPE_CONNECTED;

            if connected {
                use std::os::windows::io::FromRawHandle;
                let file = std::fs::File::from_raw_handle(pipe.0 as *mut core::ffi::c_void);
                let mut reader = BufReader::new(&file);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
                    let resp = match serde_json::from_str::<DwmIpcCommand>(line.trim()) {
                        Ok(cmd) => handle_dwm_ipc_command(cmd),
                        Err(e) => DwmIpcResponse::Error(e.to_string()),
                    };
                    if let Ok(mut out) = serde_json::to_string(&resp) {
                        out.push('\n');
                        let _ = (&file).write_all(out.as_bytes());
                        let _ = (&file).flush();
                    }
                }
                let _ = DisconnectNamedPipe(pipe);
                // `file` owns `pipe` handle now and closes it on drop
            } else {
                let _ = CloseHandle(pipe);
            }
        }
    }
}

/// Phase 11.3: Called on `dwm.exe`'s render thread inside the `CComposition::PreRender` detour.
unsafe extern "system" fn detour_dwmcore_pre_render(this_composition: *mut core::ffi::c_void) -> i32 {
    unsafe {
        apply_queued_transforms_on_render_thread();
        let orig_addr = PRE_RENDER_TRAMPOLINE.load(Ordering::Acquire);
        if orig_addr != 0 {
            let orig_fn: unsafe extern "system" fn(*mut core::ffi::c_void) -> i32 =
                std::mem::transmute(orig_addr);
            orig_fn(this_composition)
        } else {
            0
        }
    }
}

/// Phase 11.3: Called on `dwm.exe`'s render thread inside `CTopLevelWindow::ValidateVisual`.
unsafe extern "system" fn detour_udwm_validate_visual(this_window: *mut core::ffi::c_void) -> i32 {
    unsafe {
        let node_id = this_window as usize as u64;
        if node_id != 0 {
            let known = node_overrides().read().contains_key(&node_id);
            if !known {
                node_overrides().write().insert(
                    node_id,
                    DwmNodeOverride {
                        node_id,
                        hwnd: 0,
                        ..Default::default()
                    },
                );
                push_dwm_telemetry(DwmTelemetryEvent {
                    kind: DwmEventKind::WindowCreated,
                    hwnd: 0,
                    visual_node_id: node_id,
                    rect: [0, 0, 0, 0],
                    alpha: 1.0,
                    shared_handle: 0,
                });
            }
        }
        apply_queued_transforms_on_render_thread();
        let orig_addr = VALIDATE_VISUAL_TRAMPOLINE.load(Ordering::Acquire);
        if orig_addr != 0 {
            let orig_fn: unsafe extern "system" fn(*mut core::ffi::c_void) -> i32 =
                std::mem::transmute(orig_addr);
            orig_fn(this_window)
        } else {
            0
        }
    }
}

/// Applies queued `DwmNodeOverride` calls (`SetOffset`, `SetOpacity`, `SetVisible`) directly on DWM's composition thread.
unsafe fn apply_queued_transforms_on_render_thread() {
    let set_offset_ptr = FN_VISUAL_SET_OFFSET.load(Ordering::Relaxed);
    let set_opacity_ptr = FN_VISUAL_SET_OPACITY.load(Ordering::Relaxed);
    let set_visible_ptr = FN_VISUAL_SET_VISIBLE.load(Ordering::Relaxed);

    if set_offset_ptr == 0 && set_opacity_ptr == 0 && set_visible_ptr == 0 {
        return;
    }

    let snapshot: Vec<DwmNodeOverride> = node_overrides().read().values().copied().collect();
    for ov in snapshot {
        if ov.node_id < 0x10000 {
            continue;
        }
        let visual_ptr = ov.node_id as usize as *mut core::ffi::c_void;
        unsafe {
            if let Some([x, y, _w, _h]) = ov.rect {
                if set_offset_ptr != 0 {
                    let set_offset: unsafe extern "system" fn(
                        *mut core::ffi::c_void,
                        f32,
                        f32,
                        f32,
                    ) -> i32 = std::mem::transmute(set_offset_ptr);
                    let _ = set_offset(visual_ptr, x as f32, y as f32, 0.0);
                }
            }
            if let Some(alpha) = ov.opacity {
                if set_opacity_ptr != 0 {
                    let set_opacity: unsafe extern "system" fn(*mut core::ffi::c_void, f32) -> i32 =
                        std::mem::transmute(set_opacity_ptr);
                    let _ = set_opacity(visual_ptr, alpha);
                }
            }
            if set_visible_ptr != 0 {
                let set_visible: unsafe extern "system" fn(*mut core::ffi::c_void, bool) -> i32 =
                    std::mem::transmute(set_visible_ptr);
                let _ = set_visible(visual_ptr, !ov.suppress_render);
            }
        }
    }
}

/// Installs inline `TrampolineHook` detours on resolved `dwmcore.dll` and `uDWM.dll` RVAs when loaded inside `dwm.exe`.
fn install_dwmcore_hooks() {
    let shared_offsets = std::env::temp_dir().join("chickenwm_dwm_offsets.json");
    let offsets = std::fs::read_to_string(&shared_offsets)
        .ok()
        .and_then(|raw| serde_json::from_str::<DwmResolvedOffsets>(&raw).ok())
        .or_else(|| resolve_system_dwm_offsets(false).ok())
        .unwrap_or_default();

    unsafe {
        let dwmcore_wide: Vec<u16> = "dwmcore.dll\0".encode_utf16().collect();
        let udwm_wide: Vec<u16> = "uDWM.dll\0".encode_utf16().collect();
        let dwmcore_base = GetModuleHandleW(PCWSTR(dwmcore_wide.as_ptr()))
            .ok()
            .map(|h| h.0 as usize)
            .unwrap_or(0);
        let udwm_base = GetModuleHandleW(PCWSTR(udwm_wide.as_ptr()))
            .ok()
            .map(|h| h.0 as usize)
            .unwrap_or(0);

        let visual_base = if dwmcore_base != 0 {
            dwmcore_base
        } else {
            udwm_base
        };

        if visual_base != 0 {
            if let Some(rva) = offsets.rva_visual_set_offset {
                FN_VISUAL_SET_OFFSET.store(visual_base + rva as usize, Ordering::Release);
            }
            if let Some(rva) = offsets.rva_visual_set_scale {
                FN_VISUAL_SET_SCALE.store(visual_base + rva as usize, Ordering::Release);
            }
            if let Some(rva) = offsets.rva_visual_set_opacity {
                FN_VISUAL_SET_OPACITY.store(visual_base + rva as usize, Ordering::Release);
            }
            if let Some(rva) = offsets.rva_visual_set_visible {
                FN_VISUAL_SET_VISIBLE.store(visual_base + rva as usize, Ordering::Release);
            }
        }

        let mut hooks = installed_hooks().lock();
        if dwmcore_base != 0 {
            if let Some(rva) = offsets.rva_dwmcore_process_composition {
                let target = dwmcore_base + rva as usize;
                if let Ok(hook) = TrampolineHook::install(
                    target,
                    detour_dwmcore_pre_render as *const () as usize,
                    16,
                ) {
                    PRE_RENDER_TRAMPOLINE.store(hook.trampoline_fn_ptr(), Ordering::Release);
                    hooks.push(hook);
                }
            }
        }
        if udwm_base != 0 {
            if let Some(rva) = offsets.rva_top_level_validate_visual {
                let target = udwm_base + rva as usize;
                if let Ok(hook) = TrampolineHook::install(
                    target,
                    detour_udwm_validate_visual as *const () as usize,
                    16,
                ) {
                    VALIDATE_VISUAL_TRAMPOLINE.store(hook.trampoline_fn_ptr(), Ordering::Release);
                    hooks.push(hook);
                }
            }
        }
        HOOKED_FN_COUNT.store(hooks.len(), Ordering::Release);
    }
}

/// Safely restores all hooked `dwmcore.dll` and `uDWM.dll` prologues prior to DLL unload.
fn uninstall_dwmcore_hooks() {
    PRE_RENDER_TRAMPOLINE.store(0, Ordering::SeqCst);
    VALIDATE_VISUAL_TRAMPOLINE.store(0, Ordering::SeqCst);
    FN_VISUAL_SET_OFFSET.store(0, Ordering::SeqCst);
    FN_VISUAL_SET_SCALE.store(0, Ordering::SeqCst);
    FN_VISUAL_SET_OPACITY.store(0, Ordering::SeqCst);
    FN_VISUAL_SET_VISIBLE.store(0, Ordering::SeqCst);

    let mut hooks = installed_hooks().lock();
    for h in hooks.iter_mut() {
        unsafe {
            h.unhook();
        }
    }
    hooks.clear();
    HOOKED_FN_COUNT.store(0, Ordering::SeqCst);
}

/// Phase 11.2: Enables `SeDebugPrivilege` on the current process token so an elevated manager
/// can open and inject into `dwm.exe`.
pub fn enable_se_debug_privilege() -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .context("OpenProcessToken failed")?;
        let token_guard = SafeHandle::new(token).context("Invalid process token handle")?;

        let mut luid = windows::Win32::Foundation::LUID::default();
        LookupPrivilegeValueW(
            PCWSTR::null(),
            windows::core::w!("SeDebugPrivilege"),
            &mut luid,
        )
        .context("LookupPrivilegeValueW(SeDebugPrivilege) failed")?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(
            token_guard.raw(),
            false,
            Some(&tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
        .context("AdjustTokenPrivileges(SeDebugPrivilege) failed")?;
    }
    Ok(())
}

fn process_session_id(proc: HANDLE) -> Option<u32> {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(proc, TOKEN_QUERY, &mut token).is_err() {
            return None;
        }
        let token_guard = SafeHandle::new(token)?;
        let mut session_id = 0u32;
        let mut ret_len = 0u32;
        GetTokenInformation(
            token_guard.raw(),
            TokenSessionId,
            Some(&mut session_id as *mut u32 as *mut core::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        )
        .ok()?;
        Some(session_id)
    }
}

/// Finds the PID of `dwm.exe` in the current desktop session via ToolHelp32 process snapshot.
pub fn find_dwm_pid() -> Result<u32> {
    unsafe {
        let current_session = process_session_id(GetCurrentProcess()).unwrap_or(0);

        let snap = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?)
            .context("CreateToolhelp32Snapshot failed")?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut fallback_pid = None;

        if Process32FirstW(snap.raw(), &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case("dwm.exe") {
                    let pid = entry.th32ProcessID;
                    if current_session != 0 {
                        if let Ok(p_raw) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                        {
                            if let Some(p_guard) = SafeHandle::new(p_raw) {
                                if process_session_id(p_guard.raw()) == Some(current_session) {
                                    return Ok(pid);
                                }
                            }
                        }
                    }
                    fallback_pid = Some(pid);
                }
                if Process32NextW(snap.raw(), &mut entry).is_err() {
                    break;
                }
            }
        }
        if let Some(pid) = fallback_pid {
            return Ok(pid);
        }
    }
    anyhow::bail!("Could not find running dwm.exe process")
}

/// Returns `true` if `chickenwm_dwm_hook.dll` is currently injected into `dwm.exe` or answering on `\\.\pipe\dwm_ipc`.
pub fn is_dwm_hook_injected() -> bool {
    if ping_dwm_ipc().is_some() {
        return true;
    }
    let Ok(pid) = find_dwm_pid() else {
        return false;
    };
    unsafe {
        let Ok(snap_raw) = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        else {
            return false;
        };
        let Some(snap) = SafeHandle::new(snap_raw) else {
            return false;
        };
        let mut mod_entry = MODULEENTRY32W::default();
        mod_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap.raw(), &mut mod_entry).is_ok() {
            loop {
                let len = mod_entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(mod_entry.szModule.len());
                let mod_name = String::from_utf16_lossy(&mod_entry.szModule[..len]);
                if mod_name.to_ascii_lowercase().contains("chickenwm_dwm_hook") {
                    return true;
                }
                if Module32NextW(snap.raw(), &mut mod_entry).is_err() {
                    break;
                }
            }
        }
    }
    false
}

/// Injects `chickenwm_dwm_hook.dll` into `dwm.exe` (requires Administrator privileges and `dwm_hook_enabled = true`).
pub fn inject_into_dwm(dll_path: &Path) -> Result<()> {
    let signal_path = std::env::temp_dir().join("chickenwm_dwm_unhook.signal");
    let _ = std::fs::remove_file(&signal_path);

    if let Err(e) = enable_se_debug_privilege() {
        warn!("Could not enable SeDebugPrivilege prior to DWM injection: {e}");
    }

    // Pre-resolve offsets so the injected DLL can read them from temp_dir without network I/O
    let _ = resolve_system_dwm_offsets(false);

    if is_dwm_hook_injected() {
        DWM_HOOK_ACTIVE.store(true, Ordering::SeqCst);
        info!("chickenwm_dwm_hook.dll is already active inside dwm.exe");
        return Ok(());
    }

    let pid = find_dwm_pid()?;
    let full_dll = std::fs::canonicalize(dll_path)
        .unwrap_or_else(|_| dll_path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let wide_dll: Vec<u16> = full_dll.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide_dll.len() * 2;

    unsafe {
        let proc = SafeHandle::new(OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_ALL_ACCESS,
            false,
            pid,
        )?)
        .context("Failed to OpenProcess(dwm.exe) — run as Administrator to enable Experimental DWM Hook")?;

        let remote_mem = VirtualAllocEx(
            proc.raw(),
            None,
            byte_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            anyhow::bail!("VirtualAllocEx in dwm.exe failed");
        }

        let write_res = WriteProcessMemory(
            proc.raw(),
            remote_mem,
            wide_dll.as_ptr() as *const core::ffi::c_void,
            byte_len,
            None,
        );
        if write_res.is_err() {
            let _ = VirtualFreeEx(proc.raw(), remote_mem, 0, MEM_RELEASE);
            anyhow::bail!("WriteProcessMemory in dwm.exe failed");
        }

        let kernel32_wide: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let k32 = GetModuleHandleW(PCWSTR(kernel32_wide.as_ptr()))?;
        let load_lib_addr = GetProcAddress(k32, PCSTR(b"LoadLibraryW\0".as_ptr()))
            .context("Failed to locate LoadLibraryW in kernel32.dll")?;

        let thread = SafeHandle::new(CreateRemoteThread(
            proc.raw(),
            None,
            0,
            Some(std::mem::transmute(load_lib_addr)),
            Some(remote_mem),
            0,
            None,
        )?)
        .context("CreateRemoteThread(LoadLibraryW) in dwm.exe failed")?;

        let _ = WaitForSingleObject(thread.raw(), 5000);
        let _ = VirtualFreeEx(proc.raw(), remote_mem, 0, MEM_RELEASE);
    }

    DWM_HOOK_ACTIVE.store(true, Ordering::SeqCst);
    info!("Injected chickenwm_dwm_hook.dll into dwm.exe (PID {})", pid);
    Ok(())
}

/// Cleanly unhooks and ejects `chickenwm_dwm_hook.dll` from `dwm.exe`.
pub fn eject_from_dwm() -> Result<()> {
    DWM_HOOK_ACTIVE.store(false, Ordering::SeqCst);
    let signal_path = std::env::temp_dir().join("chickenwm_dwm_unhook.signal");
    let _ = std::fs::write(&signal_path, b"EJECT");
    let _ = send_dwm_ipc_command(&DwmIpcCommand::Eject);
    let _ = enable_se_debug_privilege();

    let Ok(pid) = find_dwm_pid() else {
        return Ok(());
    };

    unsafe {
        let Ok(snap_raw) = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        else {
            return Ok(());
        };
        let Some(snap) = SafeHandle::new(snap_raw) else {
            return Ok(());
        };

        let mut mod_entry = MODULEENTRY32W::default();
        mod_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut found_base = None;

        if Module32FirstW(snap.raw(), &mut mod_entry).is_ok() {
            loop {
                let len = mod_entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(mod_entry.szModule.len());
                let mod_name = String::from_utf16_lossy(&mod_entry.szModule[..len]);
                if mod_name.to_ascii_lowercase().contains("chickenwm_dwm_hook") {
                    found_base = Some(mod_entry.modBaseAddr);
                    break;
                }
                if Module32NextW(snap.raw(), &mut mod_entry).is_err() {
                    break;
                }
            }
        }

        if let Some(base_addr) = found_base {
            // Brief grace period so in-process hooks finish restoring prologues before FreeLibrary
            std::thread::sleep(std::time::Duration::from_millis(60));
            if let Ok(proc_raw) = OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
                if let Some(proc) = SafeHandle::new(proc_raw) {
                    let kernel32_wide: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
                    if let Ok(k32) = GetModuleHandleW(PCWSTR(kernel32_wide.as_ptr())) {
                        if let Some(free_lib) = GetProcAddress(k32, PCSTR(b"FreeLibrary\0".as_ptr()))
                        {
                            if let Ok(thread_raw) = CreateRemoteThread(
                                proc.raw(),
                                None,
                                0,
                                Some(std::mem::transmute(free_lib)),
                                Some(base_addr as *const core::ffi::c_void),
                                0,
                                None,
                            ) {
                                if let Some(thread) = SafeHandle::new(thread_raw) {
                                    let _ = WaitForSingleObject(thread.raw(), 3000);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Standard Win32 DLL entry point when `chickenwm_dwm_hook.dll` is loaded into `dwm.exe`.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            UNHOOK_REQUESTED.store(false, Ordering::SeqCst);
            std::thread::spawn(|| {
                install_dwmcore_hooks();
                let stop_flag = AtomicBool::new(false);
                run_dwm_ipc_pipe_server(PIPE_NAME_DWM_IPC, &stop_flag);
                uninstall_dwmcore_hooks();
            });
        }
        DLL_PROCESS_DETACH => {
            UNHOOK_REQUESTED.store(true, Ordering::SeqCst);
            uninstall_dwmcore_hooks();
            visual_transforms().write().clear();
            node_overrides().write().clear();
        }
        _ => {}
    }
    BOOL(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_extract_system_udwm_pe_signature() {
        let udwm = Path::new(r"C:\Windows\System32\uDWM.dll");
        if udwm.exists() {
            let sig = extract_pe_pdb_signature(udwm)
                .expect("should extract RSDS signature from uDWM.dll");
            assert!(sig.pdb_name.to_ascii_lowercase().contains("udwm"));
            assert!(!sig.guid_age_hex.is_empty());
            assert!(sig
                .symbol_server_url()
                .starts_with("https://msdl.microsoft.com/download/symbols/"));
        }
    }

    #[test]
    fn test_trampoline_detour_roundtrip() {
        unsafe {
            let buf = VirtualAlloc(None, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            assert!(!buf.is_null());
            let slice = std::slice::from_raw_parts_mut(buf as *mut u8, 32);
            for (i, b) in slice.iter_mut().enumerate() {
                *b = (i as u8) ^ 0x5A;
            }
            let orig_copy = slice.to_vec();

            let mut hook = TrampolineHook::install(buf as usize, (buf as usize) + 32, 16)
                .expect("should install trampoline hook");
            assert_eq!(slice[0], 0xFF);
            assert_eq!(slice[1], 0x25);

            hook.unhook();
            assert_eq!(slice, orig_copy.as_slice());
            let _ = VirtualFree(buf, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn test_dwm_ipc_pipe_roundtrip_and_telemetry() {
        let test_pipe = format!(r"\\.\pipe\dwm_ipc_test_{}", std::process::id());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = Arc::clone(&stop);
        let pipe_srv = test_pipe.clone();

        let srv_handle = std::thread::spawn(move || {
            run_dwm_ipc_pipe_server(&pipe_srv, &stop_srv);
        });

        std::thread::sleep(std::time::Duration::from_millis(30));

        // 1. Ping -> Pong
        let pong = send_dwm_ipc_command_to(&test_pipe, &DwmIpcCommand::Ping)
            .expect("should ping dwm_ipc test pipe");
        assert!(matches!(pong, DwmIpcResponse::Pong { .. }));

        // 2. SetPosition -> emits TransformChanged telemetry and updates node override
        let ack = send_dwm_ipc_command_to(
            &test_pipe,
            &DwmIpcCommand::SetPosition {
                node_id: 42,
                hwnd: 0x1234,
                x: 10,
                y: 20,
                w: 800,
                h: 600,
            },
        )
        .expect("should send SetPosition");
        assert_eq!(ack, DwmIpcResponse::Ack);

        // 3. DrainTelemetry -> receives TransformChanged event
        let telem = send_dwm_ipc_command_to(&test_pipe, &DwmIpcCommand::DrainTelemetry)
            .expect("should drain telemetry");
        match telem {
            DwmIpcResponse::Telemetry(events) => {
                assert!(!events.is_empty());
                assert_eq!(events[0].hwnd, 0x1234);
                assert_eq!(events[0].rect, [10, 20, 800, 600]);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // 4. Shut down server cleanly
        stop.store(true, Ordering::SeqCst);
        let _ = send_dwm_ipc_command_to(&test_pipe, &DwmIpcCommand::Ping);
        let _ = srv_handle.join();
    }
}
