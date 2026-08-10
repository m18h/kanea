// Two modes by argv[1]: default = long-running idle; "hog" = allocate without
// bound so the cgroup memory cap must OOM-kill it (spike check G).
fn main() {
    if std::env::args().nth(1).as_deref() == Some("hog") {
        let mut v: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut chunk = vec![0u8; 1 << 20]; // 1 MiB
            for i in (0..chunk.len()).step_by(4096) { chunk[i] = 1; } // touch pages
            v.push(chunk);
        }
    }
    println!("kanea-spike-wasm: up");
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}
