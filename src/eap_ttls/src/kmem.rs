//! kmem.rs - Direct /dev/kmem access and mt7615_ap kernel data structures.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub struct KmemDevice {
    file: File,
    pub text_base: u32,
    pub bss_base: u32,
}

#[cfg(target_arch = "arm")]
unsafe fn arm_llseek(fd: i32, addr: u32) -> Result<(), i32> {
    let mut result: u64 = 0;
    let ret: i32;
    let whence: u32 = 0; // SEEK_SET
    core::arch::asm!(
        "mov r4, {whence}",
        "svc #0",
        in("r0") fd,
        in("r1") 0u32, // offset_high MUST be 0 unsigned! Never sign-extended.
        in("r2") addr, // offset_low
        in("r3") &mut result as *mut u64,
        whence = in(reg) whence,
        in("r7") 140i32, // __NR__llseek
        lateout("r0") ret,
        out("r4") _,
        options(nostack)
    );
    if ret < 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

#[cfg(not(target_arch = "arm"))]
unsafe fn arm_llseek(fd: i32, addr: u32) -> Result<(), i32> {
    let ret = libc::lseek(fd, addr as libc::off_t, libc::SEEK_SET);
    if ret < 0 {
        Err(-1)
    } else {
        Ok(())
    }
}

fn parse_hex_file(path: &Path) -> Result<u32, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read section file '{}': {}", path.display(), e))?;
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16)
        .map_err(|e| format!("Failed to parse hex string '{}' in '{}': {}", s, path.display(), e))
}

impl KmemDevice {
    pub fn open(kmem_path: &str, modules_dir: &str, read_only: bool) -> Result<Self, String> {
        let text_path = Path::new(modules_dir).join(".text");
        let bss_path = Path::new(modules_dir).join(".bss");

        let text_base = parse_hex_file(&text_path)?;
        let bss_base = parse_hex_file(&bss_path)?;

        let mut opts = File::options();
        opts.read(true);
        if !read_only {
            opts.write(true);
        }

        let file = opts
            .open(kmem_path)
            .map_err(|e| format!("Failed to open kmem device '{}': {}", kmem_path, e))?;

        Ok(Self {
            file,
            text_base,
            bss_base,
        })
    }

    pub fn read_u8(&self, addr: u32) -> Result<u8, String> {
        let fd = self.file.as_raw_fd();
        let mut b = [0u8; 1];
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::read(fd, b.as_mut_ptr() as *mut _, 1);
            if r != 1 {
                return Err(format!("read_u8 at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(b[0])
    }

    pub fn read_u32(&self, addr: u32) -> Result<u32, String> {
        let fd = self.file.as_raw_fd();
        let mut b = [0u8; 4];
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::read(fd, b.as_mut_ptr() as *mut _, 4);
            if r != 4 {
                return Err(format!("read_u32 at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_bytes(&self, addr: u32, buf: &mut [u8]) -> Result<(), String> {
        let fd = self.file.as_raw_fd();
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len());
            if r as usize != buf.len() {
                return Err(format!("read_bytes at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(())
    }

    pub fn write_u8(&self, addr: u32, val: u8) -> Result<(), String> {
        let fd = self.file.as_raw_fd();
        let b = [val];
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::write(fd, b.as_ptr() as *const _, 1);
            if r != 1 {
                return Err(format!("write_u8 at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(())
    }

    pub fn write_u32(&self, addr: u32, val: u32) -> Result<(), String> {
        let fd = self.file.as_raw_fd();
        let b = val.to_le_bytes();
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::write(fd, b.as_ptr() as *const _, 4);
            if r != 4 {
                return Err(format!("write_u32 at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(())
    }

    pub fn write_bytes(&self, addr: u32, data: &[u8]) -> Result<(), String> {
        let fd = self.file.as_raw_fd();
        unsafe {
            arm_llseek(fd, addr).map_err(|e| format!("_llseek to 0x{:08x} failed: {}", addr, e))?;
            let r = libc::write(fd, data.as_ptr() as *const _, data.len());
            if r as usize != data.len() {
                return Err(format!("write_bytes at 0x{:08x} returned {}", addr, r));
            }
        }
        Ok(())
    }

    /// Chase pointer: pAd = *(B + 0xf74), wcid = *(pAd + 0x1f790c), entry = pAd + 0x450 + wcid * 0x12e8
    pub fn get_pointers(&self) -> Result<(u32, u8, u32), String> {
        let pad = self.read_u32(self.bss_base + 0xf74)?;
        let wcid = self.read_u8(pad + 0x1f790c)?;
        let entry = pad + 0x450 + (wcid as u32) * 0x12e8;
        Ok((pad, wcid, entry))
    }

    /// Execute pre-EAP preparation: clear mt7615 cg_hdswitch_on (B + 0xf1c) and patch jt0 (T + 0x90230)
    pub fn pre_eap_prep(&self, skip_jt_poke: bool) -> Result<(), String> {
        // 1. Check cg_hdswitch_on at B + 0xf1c
        let cg = self.read_u8(self.bss_base + 0xf1c)?;
        if cg == 0x01 {
            self.write_u8(self.bss_base + 0xf1c, 0x00)?;
            let v = self.read_u8(self.bss_base + 0xf1c)?;
            if v != 0x00 {
                return Err(format!("Failed to clear cg_hdswitch_on: still 0x{:02x}", v));
            }
            eprintln!("[kmem] cg_hdswitch_on at 0x{:08x} cleared to 00", self.bss_base + 0xf1c);
        } else if cg == 0x00 {
            eprintln!("[kmem] cg_hdswitch_on at 0x{:08x} is already 00", self.bss_base + 0xf1c);
        } else {
            eprintln!("[kmem] cg_hdswitch_on at 0x{:08x} is 0x{:02x}", self.bss_base + 0xf1c, cg);
        }

        // 2. Patch jt0 jump table unless skipped
        if !skip_jt_poke {
            let jt0_addr = self.text_base + 0x90230;
            let jt0 = self.read_u32(jt0_addr)?;
            let target_from = self.text_base + 0x902a4;
            let target_to = self.text_base + 0x90244;

            if jt0 == target_from {
                self.write_u32(jt0_addr, target_to)?;
                let v = self.read_u32(jt0_addr)?;
                if v != target_to {
                    return Err(format!("Failed to patch jt0 at 0x{:08x}: read 0x{:08x}", jt0_addr, v));
                }
                eprintln!("[kmem] Patched jt0 at 0x{:08x}: 0x{:08x} -> 0x{:08x}", jt0_addr, jt0, target_to);
            } else if jt0 == target_to {
                eprintln!("[kmem] jt0 at 0x{:08x} is already patched to 0x{:08x}", jt0_addr, target_to);
            } else {
                return Err(format!(
                    "Unexpected jt0 at 0x{:08x}: 0x{:08x} (expected 0x{:08x} or 0x{:08x})",
                    jt0_addr, jt0, target_from, target_to
                ));
            }
        }

        Ok(())
    }

    /// Inject 32-byte PMK and clear PrivacyFilter.
    pub fn inject_pmk(&self, pmk: &[u8; 32]) -> Result<(), String> {
        let (pad, wcid, entry) = self.get_pointers()?;

        // Verify entry magic == 0x00004001
        let magic = self.read_u32(entry)?;
        if magic != 0x00004001 {
            return Err(format!(
                "Abort: [pEntry] magic at 0x{:08x} is 0x{:08x} (expected 0x00004001)",
                entry, magic
            ));
        }

        // 1. Write PMK to wdev.SecConfig.PMK (pad + 0x14bfc2)
        let wdev_pmk_addr = pad + 0x14bfc2;
        self.write_bytes(wdev_pmk_addr, pmk)?;
        let mut check1 = [0u8; 32];
        self.read_bytes(wdev_pmk_addr, &mut check1)?;
        if &check1 != pmk {
            return Err(format!("PMK verification failed at wdev.SecConfig.PMK (0x{:08x})", wdev_pmk_addr));
        }

        // 2. Write PMK to pEntry.PMK (entry + 0x202)
        let entry_pmk_addr = entry + 0x202;
        self.write_bytes(entry_pmk_addr, pmk)?;
        let mut check2 = [0u8; 32];
        self.read_bytes(entry_pmk_addr, &mut check2)?;
        if &check2 != pmk {
            return Err(format!("PMK verification failed at pEntry.PMK (0x{:08x})", entry_pmk_addr));
        }

        eprintln!(
            "[kmem] PMK injected & verified at wdev (0x{:08x}) and entry wcid={} (0x{:08x})",
            wdev_pmk_addr, wcid, entry_pmk_addr
        );

        // 3. Clear PrivacyFilter at entry + 0x93c if == 1
        let pf_addr = entry + 0x93c;
        let pf = self.read_u32(pf_addr)?;
        if pf == 1 {
            self.write_u32(pf_addr, 0u32)?;
            let v = self.read_u32(pf_addr)?;
            if v != 0 {
                return Err(format!("Failed to clear PrivacyFilter at 0x{:08x}", pf_addr));
            }
            eprintln!("[kmem] PrivacyFilter at 0x{:08x} cleared to 0", pf_addr);
        }

        Ok(())
    }

    /// Read-only diagnostic verification of kmem structures.
    pub fn verify_kmem_diagnostics(&self) -> Result<(), String> {
        let jt0_addr = self.text_base + 0x90230;
        let jt0 = self.read_u32(jt0_addr)?;
        let target_from = self.text_base + 0x902a4;
        let target_to = self.text_base + 0x90244;
        if jt0 != target_from && jt0 != target_to {
            return Err(format!(
                "Unexpected jt0 at 0x{:08x}: 0x{:08x} (expected 0x{:08x} or 0x{:08x})",
                jt0_addr, jt0, target_from, target_to
            ));
        }

        let (pad, wcid, entry) = self.get_pointers()?;
        if pad == 0 {
            return Err("pAd pointer is NULL (0x00000000)".to_string());
        }

        let entry_magic = self.read_u32(entry)?;
        let pf = self.read_u32(entry + 0x93c)?;

        println!("text: 0x{:08x}", self.text_base);
        println!("bss: 0x{:08x}", self.bss_base);
        println!("jt0: 0x{:08x}", jt0);
        println!("pAd: 0x{:08x}", pad);
        println!("wcid: 0x{:02x}", wcid);
        println!("[pEntry]: 0x{:08x}", entry_magic);
        println!("PrivacyFilter: 0x{:08x}", pf);

        Ok(())
    }
}
