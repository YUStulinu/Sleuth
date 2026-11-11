//! sleuth-parallel: runs one `sleuth fuzz` worker per core on the same target with a shared,
//! curated corpus (see lib.rs), aggregates their statistics and crashes, and serves them to
//! the dashboard over HTTP.
//!
//!   sleuth-parallel --fuzzer build/sleuth -t build/png/sleuth -i targets/png/seeds -o out/png-par
//!                   [--workers N] [--time S] [--dict FILE] [--port 8700] [--web web/dist]
//!                   [--linger] [-- extra sleuth fuzz options]
//!
//! Output: OUT/worker-K/ (each worker's own output), OUT/sync/ (the exchange), OUT/corpus/ (the
//! global corpus), OUT/summary.json, OUT/timeline.json, OUT/crashes.json.

use serde::Serialize;
use sleuth_parallel::*;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Args {
    fuzzer: String,
    target: String,
    seeds: Vec<String>,
    out: PathBuf,
    workers: usize,
    time_s: f64,
    dict: Option<String>,
    port: Option<u16>,
    web: PathBuf,
    linger: bool,
    extra: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: sleuth-parallel --fuzzer SLEUTH -t TARGET -i SEEDS [-i ...] -o OUT [--workers N] [--time S]\n\
         \x20                      [--dict FILE] [--port P] [--web DIR] [--linger] [-- sleuth fuzz options]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        fuzzer: String::new(),
        target: String::new(),
        seeds: vec![],
        out: PathBuf::from("out"),
        workers: thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        time_s: 0.0,
        dict: None,
        port: None,
        web: PathBuf::from("web/dist"),
        linger: false,
        extra: vec![],
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let k = argv[i].as_str();
        let mut val = || {
            i += 1;
            argv.get(i).cloned().unwrap_or_else(|| usage())
        };
        match k {
            "--fuzzer" => a.fuzzer = val(),
            "-t" => a.target = val(),
            "-i" => a.seeds.push(val()),
            "-o" => a.out = PathBuf::from(val()),
            "--workers" => a.workers = val().parse().unwrap_or_else(|_| usage()),
            "--time" => a.time_s = val().parse().unwrap_or_else(|_| usage()),
            "--dict" => a.dict = Some(val()),
            "--port" => a.port = Some(val().parse().unwrap_or_else(|_| usage())),
            "--web" => a.web = PathBuf::from(val()),
            "--linger" => a.linger = true,
            "--" => {
                a.extra = argv[i + 1..].to_vec();
                break;
            }
            _ => usage(),
        }
        i += 1;
    }
    if a.fuzzer.is_empty() || a.target.is_empty() || a.workers == 0 {
        usage();
    }
    a
}

#[derive(Serialize, Clone)]
struct Point {
    t: f64,
    execs: u64,
    edges: usize,
    corpus: usize,
    crashes: usize,
}

#[derive(Default)]
struct Shared {
    summary: String,
    timeline: String,
    crashes: String,
    workers: String,
}

fn spawn_worker(a: &Args, k: usize) -> std::io::Result<Child> {
    let dir = a.out.join(format!("worker-{k}"));
    fs::create_dir_all(&dir)?;
    let mut cmd = Command::new(&a.fuzzer);
    cmd.arg("fuzz").arg("-t").arg(&a.target);
    for s in &a.seeds {
        cmd.arg("-i").arg(s);
    }
    cmd.arg("-o").arg(&dir);
    cmd.arg("--sync-dir").arg(a.out.join("sync")).arg("--worker-id").arg(k.to_string());
    if a.time_s > 0.0 {
        cmd.arg("--time").arg(a.time_s.to_string());
    }
    if let Some(d) = &a.dict {
        cmd.arg("--dict").arg(d);
    }
    cmd.args(&a.extra);
    let log = fs::File::create(dir.join("log.txt"))?;
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(log);
    cmd.spawn()
}

fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}

fn respond(mut s: TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
}

fn serve(port: u16, web: PathBuf, shared: Arc<Mutex<Shared>>) {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {e}");
            return;
        }
    };
    eprintln!("dashboard: http://127.0.0.1:{port}/");
    for stream in listener.incoming().flatten() {
        let web = web.clone();
        let shared = shared.clone();
        thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                return;
            }
            let mut parts = line.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
            if method != "GET" {
                return respond(stream, "405 Method Not Allowed", "text/plain", b"GET only\n");
            }
            let path = path.split('?').next().unwrap_or("/");
            let api = {
                let s = shared.lock().unwrap();
                match path {
                    "/api/summary" => Some(s.summary.clone()),
                    "/api/timeline" => Some(s.timeline.clone()),
                    "/api/crashes" => Some(s.crashes.clone()),
                    "/api/workers" => Some(s.workers.clone()),
                    _ => None,
                }
            };
            if let Some(body) = api {
                return respond(stream, "200 OK", "application/json", body.as_bytes());
            }
            // Static files of the dashboard; no way out of the web directory.
            let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
            if rel.split('/').any(|c| c == ".." || c.contains('\\') || c.contains(':')) {
                return respond(stream, "400 Bad Request", "text/plain", b"bad path\n");
            }
            let file = web.join(rel);
            match fs::read(&file) {
                Ok(b) => respond(stream, "200 OK", content_type(&file), &b),
                Err(_) => respond(stream, "404 Not Found", "text/plain", b"not found\n"),
            }
        });
    }
}

fn main() {
    let a = parse_args();
    fs::create_dir_all(&a.out).expect("cannot create the output directory");
    let mut curator = Curator::new(&a.out.join("sync"), Some(&a.out.join("corpus"))).expect("cannot create the sync directory");
    let shared = Arc::new(Mutex::new(Shared::default()));
    if let Some(port) = a.port {
        let (web, sh) = (a.web.clone(), shared.clone());
        thread::spawn(move || serve(port, web, sh));
    }
    let start = Instant::now();
    let mut children: Vec<Child> = Vec::new();
    for k in 0..a.workers {
        match spawn_worker(&a, k) {
            Ok(c) => children.push(c),
            Err(e) => {
                eprintln!("cannot start worker {k}: {e}");
                std::process::exit(1);
            }
        }
    }
    eprintln!("{} workers started on {}", a.workers, a.target);
    let mut timeline: Vec<Point> = Vec::new();
    let mut last_point = -5.0f64;
    let mut running = true;
    while running {
        thread::sleep(Duration::from_millis(1000));
        running = children.iter_mut().any(|c| matches!(c.try_wait(), Ok(None)));
        if let Err(e) = curator.scan() {
            eprintln!("scan: {e}");
        }
        let dirs: Vec<(usize, PathBuf)> = (0..a.workers).map(|k| (k, a.out.join(format!("worker-{k}")))).collect();
        let stats: Vec<WorkerStats> = dirs.iter().filter_map(|(_, d)| read_worker_stats(d)).collect();
        let crashes = merge_crashes(&dirs.iter().map(|(k, d)| (*k, read_worker_crashes(d))).collect::<Vec<_>>());
        let t = start.elapsed().as_secs_f64();
        let summary = summarize(&stats, &curator, crashes.len(), t);
        if t - last_point >= 5.0 || !running {
            last_point = t;
            timeline.push(Point { t, execs: summary.execs, edges: summary.edges_global, corpus: summary.corpus_global, crashes: crashes.len() });
            eprintln!(
                "[{t:7.1}s] {} execs ({:.0}/s) global edges {} corpus {} crashes {} workers done {}/{}",
                summary.execs, summary.execs_per_s, summary.edges_global, summary.corpus_global, crashes.len(), summary.workers_done, a.workers
            );
        }
        let s_summary = serde_json::to_string_pretty(&summary).unwrap();
        let s_timeline = serde_json::to_string(&timeline).unwrap();
        let s_crashes = serde_json::to_string_pretty(&crashes).unwrap();
        let s_workers = serde_json::to_string(&stats).unwrap();
        for (name, body) in [("summary.json", &s_summary), ("timeline.json", &s_timeline), ("crashes.json", &s_crashes)] {
            let tmp = a.out.join(format!("{name}.tmp"));
            if fs::write(&tmp, body).is_ok() {
                let _ = fs::rename(&tmp, a.out.join(name));
            }
        }
        let mut sh = shared.lock().unwrap();
        *sh = Shared { summary: s_summary, timeline: s_timeline, crashes: s_crashes, workers: s_workers };
    }
    eprintln!("all workers finished after {:.1}s", start.elapsed().as_secs_f64());
    if a.linger && a.port.is_some() {
        eprintln!("still serving the dashboard (Ctrl-C to stop)");
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
}
