//! main.rs - Standalone static soft-float ARMv7 WPA2-Enterprise EAP-TTLS + PAP authenticator
//! and in-kernel PMK injector for ZTE F680 / mt7615_ap.

mod crypto;
mod der;
mod diameter;
mod kmem;
mod transport;
mod ttls;

use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

use crypto::build_client_config;
use kmem::KmemDevice;
use transport::{parse_mac, EapolTransport, MockSocketTransport, RawSocketTransport};
use ttls::run_eap_ttls;

struct Config {
    iface: String,
    bssid: Option<[u8; 6]>,
    identity: Option<String>,
    password_file: Option<String>,
    ca_path: Option<String>,
    anon_identity: Option<String>,
    timeout_secs: u64,
    skip_jt_poke: bool,
    verify_kmem: bool,
    mock_socket: Option<String>,
    kmem_path: String,
    modules_dir: String,
    iface_mac: Option<[u8; 6]>,
    force_1970_clock: bool,
    tls12_only: bool,
    fragment_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            iface: "apcli0".to_string(),
            bssid: None,
            identity: None,
            password_file: None,
            ca_path: None,
            anon_identity: None,
            timeout_secs: 30,
            skip_jt_poke: false,
            verify_kmem: false,
            mock_socket: None,
            kmem_path: "/dev/kmem".to_string(),
            modules_dir: "/sys/module/mt7615_ap/sections".to_string(),
            iface_mac: None,
            force_1970_clock: false,
            tls12_only: false,
            fragment_size: ttls::DEFAULT_CHUNK_SIZE,
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: eap_ttls [OPTIONS]\n\n\
        Options:\n  \
          --iface <iface>          Network interface (default: apcli0)\n  \
          --bssid <MAC>            Access point BSSID (AA:BB:CC:DD:EE:FF)\n  \
          --identity <user@domain> Inner identity / username\n  \
          --password-file <path>   Password file path or '-' for stdin\n  \
          --ca <path/to/ca.pem>    Optional PEM root CA certificate\n  \
          --anon-identity <str>    Optional outer EAP identity (defaults to --identity)\n  \
          --timeout <sec>          Authentication timeout in seconds (default: 30)\n  \
          --skip-jt-poke           Do not patch .text + 0x90230\n  \
          --verify-kmem            Diagnostic read-only inspection of mt7615 kmem\n  \
          --mock-socket <path>     Offline mock Unix domain datagram socket\n  \
          --kmem-path <path>       Custom kmem file path (default: /dev/kmem)\n  \
          --modules-dir <path>     Custom module sections dir (default: /sys/module/mt7615_ap/sections)\n  \
          --iface-mac <MAC>        Override interface MAC address\n  \
          --force-1970-clock       Simulate stuck 1970 system clock\n  \
          --tls12-only             Restrict TLS version to TLS 1.2\n  \
          --fragment-size <bytes>  Maximum EAP-TTLS fragment chunk size (default: 1000)\n  \
          -h, --help               Show this help message"
    );
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iface" => {
                cfg.iface = args.next().ok_or("Missing value for --iface")?;
            }
            "--bssid" => {
                let s = args.next().ok_or("Missing value for --bssid")?;
                cfg.bssid = Some(parse_mac(&s)?);
            }
            "--identity" => {
                cfg.identity = Some(args.next().ok_or("Missing value for --identity")?);
            }
            "--password-file" => {
                cfg.password_file = Some(args.next().ok_or("Missing value for --password-file")?);
            }
            "--ca" => {
                cfg.ca_path = Some(args.next().ok_or("Missing value for --ca")?);
            }
            "--anon-identity" => {
                cfg.anon_identity = Some(args.next().ok_or("Missing value for --anon-identity")?);
            }
            "--timeout" => {
                let s = args.next().ok_or("Missing value for --timeout")?;
                cfg.timeout_secs = s.parse().map_err(|e| format!("Invalid --timeout '{}': {}", s, e))?;
            }
            "--skip-jt-poke" => {
                cfg.skip_jt_poke = true;
            }
            "--verify-kmem" => {
                cfg.verify_kmem = true;
            }
            "--mock-socket" => {
                cfg.mock_socket = Some(args.next().ok_or("Missing value for --mock-socket")?);
            }
            "--kmem-path" => {
                cfg.kmem_path = args.next().ok_or("Missing value for --kmem-path")?;
            }
            "--modules-dir" => {
                cfg.modules_dir = args.next().ok_or("Missing value for --modules-dir")?;
            }
            "--force-1970-clock" => {
                cfg.force_1970_clock = true;
            }
            "--tls12-only" => {
                cfg.tls12_only = true;
            }
            "--fragment-size" => {
                let s = args.next().ok_or("Missing value for --fragment-size")?;
                cfg.fragment_size = s.parse().map_err(|e| format!("Invalid --fragment-size '{}': {}", s, e))?;
            }
            "--iface-mac" => {
                let s = args.next().ok_or("Missing value for --iface-mac")?;
                cfg.iface_mac = Some(parse_mac(&s)?);
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other => {
                return Err(format!("Unknown option '{}'", other));
            }
        }
    }

    Ok(cfg)
}

fn read_password(path: &str) -> Result<String, String> {
    let mut pwd = String::new();
    if path == "-" {
        io::stdin()
            .read_to_string(&mut pwd)
            .map_err(|e| format!("Failed to read password from stdin: {}", e))?;
    } else {
        pwd = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read password file '{}': {}", path, e))?;
    }
    // Trim trailing newline / carriage return
    let trimmed = pwd.trim_end_matches(&['\r', '\n'][..]).to_string();
    if trimmed.is_empty() {
        return Err("Password is empty".into());
    }
    Ok(trimmed)
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_usage();
            process::exit(1);
        }
    };

    // Diagnostic mode: verify kmem structures and exit
    if cfg.verify_kmem {
        match KmemDevice::open(&cfg.kmem_path, &cfg.modules_dir, true) {
            Ok(kmem) => {
                if let Err(e) = kmem.verify_kmem_diagnostics() {
                    eprintln!("Error reading kmem diagnostics: {}", e);
                    process::exit(1);
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error opening kmem for verification: {}", e);
                process::exit(1);
            }
        }
    }

    // Required arguments for authentication run
    let bssid = match cfg.bssid {
        Some(b) => b,
        None => {
            eprintln!("Error: --bssid is required for authentication");
            process::exit(1);
        }
    };

    let identity = match cfg.identity {
        Some(ref id) => id.clone(),
        None => {
            eprintln!("Error: --identity is required for authentication");
            process::exit(1);
        }
    };

    let password_file = match cfg.password_file {
        Some(ref pf) => pf.clone(),
        None => {
            eprintln!("Error: --password-file is required for authentication");
            process::exit(1);
        }
    };

    let password = match read_password(&password_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            process::exit(1);
        }
    };

    let anon_identity = cfg.anon_identity.unwrap_or_else(|| identity.clone());

    eprintln!("[eap_ttls] Starting authentication on iface '{}' to BSSID {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        cfg.iface, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]
    );

    // 1. Open kmem and run pre-EAP prep (cg_hdswitch_on clear + jt0 jump table patch)
    let kmem = match KmemDevice::open(&cfg.kmem_path, &cfg.modules_dir, false) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: Cannot open kmem device: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = kmem.pre_eap_prep(cfg.skip_jt_poke) {
        eprintln!("Error in pre-EAP prep: {}", e);
        process::exit(1);
    }

    // 2. Build TLS ClientConfig
    let client_config = match build_client_config(cfg.ca_path.as_deref(), cfg.force_1970_clock, cfg.tls12_only) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error initializing TLS configuration: {}", e);
            process::exit(1);
        }
    };

    // 3. Initialize transport (AF_PACKET or MockSocket)
    let mut transport: Box<dyn EapolTransport> = if let Some(ref mock_path) = cfg.mock_socket {
        let mac = cfg.iface_mac.unwrap_or([0x12, 0x00, 0x7d, 0xf6, 0xc9, 0xf8]);
        match MockSocketTransport::new(mock_path, bssid, mac) {
            Ok(t) => Box::new(t),
            Err(e) => {
                eprintln!("Error initializing mock transport: {}", e);
                process::exit(1);
            }
        }
    } else {
        match RawSocketTransport::new(&cfg.iface, bssid, cfg.iface_mac) {
            Ok(t) => Box::new(t),
            Err(e) => {
                eprintln!("Error initializing raw socket transport: {}", e);
                process::exit(1);
            }
        }
    };

    // 4. Run EAP-TTLS state machine
    match run_eap_ttls(
        &mut *transport,
        &kmem,
        client_config,
        &identity,
        &password,
        &anon_identity,
        cfg.timeout_secs,
        cfg.fragment_size,
    ) {
        Ok(()) => {
            eprintln!("[eap_ttls] Authentication SUCCESS: PMK injected and ready for driver 4-way handshake.");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("[eap_ttls] Authentication FAILED: {}", e);
            process::exit(1);
        }
    }
}
