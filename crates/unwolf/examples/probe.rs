//! Development probe: open an archive with one mode and decode every file
//! in memory. Usage: probe <archive> <mode index> [max files]
use std::path::Path;
use unwolf::dxa::{Archive, OpenParams};
use unwolf::modes::default_modes;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: probe <archive> <mode index> [max files]");
        std::process::exit(2);
    }
    let modes = default_modes();
    let Some(m) = args[2].parse::<usize>().ok().and_then(|i| modes.get(i)) else {
        eprintln!("bad mode index");
        std::process::exit(2);
    };
    let max: usize = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);
    let t = std::time::Instant::now();
    let arc = match Archive::open(
        Path::new(&args[1]),
        &OpenParams {
            format: m.format,
            key: &m.key,
        },
    ) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("open failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "mode {} cv={} entries={} ({:?})",
        m.name,
        arc.crypt_version,
        arc.entries.len(),
        t.elapsed()
    );
    let (mut ok, mut bad, mut bytes) = (0, 0, 0u64);
    for e in arc.entries.iter().filter(|e| e.data.is_some()).take(max) {
        let Some(f) = &e.data else { continue };
        match arc.read_file(f) {
            Ok(b) => {
                ok += 1;
                bytes += b.len() as u64;
                if ok <= 5 {
                    println!(
                        "  {} {} {:02X?}",
                        e.path.display(),
                        b.len(),
                        &b[..b.len().min(16)]
                    );
                }
            }
            Err(err) => {
                bad += 1;
                if bad <= 5 {
                    println!("  FAIL {}: {err} {:?}", e.path.display(), f);
                }
            }
        }
    }
    println!("ok={ok} bad={bad} bytes={bytes} ({:?})", t.elapsed());
}
