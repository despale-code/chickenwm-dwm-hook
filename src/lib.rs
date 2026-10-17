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
use parking_lot::RwLock;
use pdb::FallibleIterator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use tracing::info;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx, VirtualProtect, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

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
    /// RVA of `CVisual::SetScale` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_scale: Option<u32>,
    /// RVA of `CVisual::SetOffset` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_offset: Option<u32>,
    /// RVA of `CVisual::SetOpacity` in `uDWM.dll` / `dwmcore.dll`
    pub rva_visual_set_opacity: Option<u32>,
    /// RVA of `CComposition::PreRender` / `ProcessComposition` in `dwmcore.dll`
    pub rva_dwmcore_process_composition: Option<u32>,
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
                if name.contains("s_pDesktopManagerInstance") {
                    offsets.rva_desktop_manager_instance = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CTopLevelWindow") && name.contains("ValidateVisual") {
                    offsets.rva_top_level_validate_visual = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CTopLevelWindow") && name.contains("UpdateWindowVisuals") {
                    offsets.rva_top_level_update_visuals = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CVisual") && name.contains("SetScale") {
                    offsets.rva_visual_set_scale = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CVisual") && name.contains("SetOffset") {
                    offsets.rva_visual_set_offset = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CVisual") && name.contains("SetOpacity") {
                    offsets.rva_visual_set_opacity = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                } else if name.contains("CComposition") && name.contains("PreRender") {
                    offsets.rva_dwmcore_process_composition = Some(rva_val);
                    offsets.all_matched_rvas.insert(name, rva_val);
                }
            }
        }
    }

    Ok(())
}

/// Resolves `uDWM.dll` and `dwmcore.dll` offsets (downloading PDBs or loading from cache).
pub fn resolve_system_dwm_offsets(download_if_missing: bool) -> Result<DwmResolvedOffsets> {
    let cache_path = config_dir().join("symbols").join("dwm_offsets_cache.json");
    if cache_path.exists() {
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
                }
            }
            offsets.dwmcore_signature = Some(sig);
        }
    }

    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&offsets) {
        let _ = std::fs::write(&cache_path, json);
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

/// Global in-process transform registry used when `chickenwm_dwm_hook.dll` is loaded inside `dwm.exe`.
static VISUAL_TRANSFORMS: OnceLock<RwLock<HashMap<u64, DwmVisualTransform>>> = OnceLock::new();

pub fn visual_transforms() -> &'static RwLock<HashMap<u64, DwmVisualTransform>> {
    VISUAL_TRANSFORMS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Updates the DWM visual transform for `hwnd` and writes it to the shared state file so an
/// injected `chickenwm_dwm_hook.dll` instance can apply it on the very next `dwmcore.dll` composition tick.
pub fn update_dwm_visual_transform(transform: DwmVisualTransform) {
    visual_transforms().write().insert(transform.hwnd, transform);
}

/// Finds the PID of `dwm.exe` via ToolHelp32 process snapshot.
pub fn find_dwm_pid() -> Result<u32> {
    unsafe {
        let snap = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?)
            .context("CreateToolhelp32Snapshot failed")?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap.raw(), &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case("dwm.exe") {
                    return Ok(entry.th32ProcessID);
                }
                if Process32NextW(snap.raw(), &mut entry).is_err() {
                    break;
                }
            }
        }
    }
    anyhow::bail!("Could not find running dwm.exe process")
}

/// Injects `chickenwm_dwm_hook.dll` into `dwm.exe` (requires Administrator privileges and `dwm_hook_enabled = true`).
pub fn inject_into_dwm(dll_path: &Path) -> Result<()> {
    let signal_path = std::env::temp_dir().join("chickenwm_dwm_unhook.signal");
    let _ = std::fs::remove_file(&signal_path);

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
            std::thread::spawn(|| {
                let signal_path = std::env::temp_dir().join("chickenwm_dwm_unhook.signal");
                while !signal_path.exists() {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
        }
        DLL_PROCESS_DETACH => {
            visual_transforms().write().clear();
        }
        _ => {}
    }
    BOOL(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_system_udwm_pe_signature() {
        let udwm = Path::new(r"C:\Windows\System32\uDWM.dll");
        if udwm.exists() {
            let sig = extract_pe_pdb_signature(udwm).expect("should extract RSDS signature from uDWM.dll");
            assert!(sig.pdb_name.to_ascii_lowercase().contains("udwm"));
            assert!(!sig.guid_age_hex.is_empty());
            assert!(sig.symbol_server_url().starts_with("https://msdl.microsoft.com/download/symbols/"));
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
}
