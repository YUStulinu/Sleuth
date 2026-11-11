//! The pieces of the parallel supervisor that do not need processes or sockets: the global
//! coverage map, corpus curation, and the aggregation of worker statistics and crashes.
//!
//! Every worker (`sleuth fuzz --sync-dir S --worker-id K`) writes each input it adds to its own
//! corpus to `S/worker-K/queue/NAME`, with the edges it covers in `NAME.edges` (one
//! `edge << 3 | bucket` number per edge). The curator reads those, keeps a global map of the
//! (edge, bucket) pairs seen by any worker, and publishes an input to `S/shared/` only when it
//! adds something to that global map. Workers import from `shared/`, so an input found by one
//! worker reaches the others once, and inputs that only repeat what is known stay private.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The (edge, hit-count bucket) pairs seen so far, as a bit set of buckets per edge.
#[derive(Default, Debug, Clone)]
pub struct GlobalMap {
    bits: HashMap<u32, u8>,
}

impl GlobalMap {
    /// Adds the edges of one input; returns how many edges and how many (edge, bucket) pairs
    /// were new.
    pub fn merge(&mut self, edges: &[u32]) -> (usize, usize) {
        let (mut new_edges, mut new_pairs) = (0, 0);
        for &x in edges {
            let (edge, bit) = (x >> 3, 1u8 << (x & 7));
            let slot = self.bits.entry(edge).or_insert(0);
            if *slot == 0 {
                new_edges += 1;
            }
            if *slot & bit == 0 {
                new_pairs += 1;
                *slot |= bit;
            }
        }
        (new_edges, new_pairs)
    }

    /// Would these edges add anything?
    pub fn is_new(&self, edges: &[u32]) -> bool {
        edges.iter().any(|&x| self.bits.get(&(x >> 3)).is_none_or(|b| b & (1 << (x & 7)) == 0))
    }

    pub fn edges(&self) -> usize {
        self.bits.len()
    }
}

/// Parses an `.edges` sidecar: whitespace-separated unsigned numbers.
pub fn parse_edges(text: &str) -> Option<Vec<u32>> {
    text.split_whitespace().map(|t| t.parse().ok()).collect()
}

/// One input published to the shared corpus.
#[derive(Debug, Clone, Serialize)]
pub struct Published {
    pub name: String,
    pub worker: usize,
    pub new_edges: usize,
    pub new_pairs: usize,
}

/// Watches the workers' queues and publishes globally new inputs.
pub struct Curator {
    sync_dir: PathBuf,
    corpus_dir: Option<PathBuf>,
    pub map: GlobalMap,
    seen: HashSet<PathBuf>,
    seq: usize,
    pub offered: usize,
    pub published: usize,
}

impl Curator {
    /// `corpus_dir`, if given, also receives a copy of every published input (the global
    /// corpus that is kept at the end of a campaign).
    pub fn new(sync_dir: &Path, corpus_dir: Option<&Path>) -> io::Result<Self> {
        fs::create_dir_all(sync_dir.join("shared"))?;
        if let Some(c) = corpus_dir {
            fs::create_dir_all(c)?;
        }
        Ok(Curator {
            sync_dir: sync_dir.to_path_buf(),
            corpus_dir: corpus_dir.map(Path::to_path_buf),
            map: GlobalMap::default(),
            seen: HashSet::new(),
            seq: 0,
            offered: 0,
            published: 0,
        })
    }

    /// One pass over every worker queue. Inputs are taken in name order (the workers number
    /// them), and only once their `.edges` sidecar exists.
    pub fn scan(&mut self) -> io::Result<Vec<Published>> {
        let mut out = Vec::new();
        let mut workers: Vec<(usize, PathBuf)> = Vec::new();
        for e in fs::read_dir(&self.sync_dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(k) = name.strip_prefix("worker-").and_then(|k| k.parse().ok()) {
                workers.push((k, e.path().join("queue")));
            }
        }
        workers.sort();
        for (k, queue) in workers {
            let Ok(rd) = fs::read_dir(&queue) else { continue };
            let mut names: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_none_or(|x| x != "edges" && x != "tmp"))
                .collect();
            names.sort();
            for path in names {
                if self.seen.contains(&path) {
                    continue;
                }
                let sidecar = PathBuf::from(format!("{}.edges", path.display()));
                let Ok(text) = fs::read_to_string(&sidecar) else { continue };
                let Some(edges) = parse_edges(&text) else { continue };
                self.seen.insert(path.clone());
                self.offered += 1;
                if !self.map.is_new(&edges) {
                    continue;
                }
                let (new_edges, new_pairs) = self.map.merge(&edges);
                let base = path.file_name().unwrap().to_string_lossy().to_string();
                // "-wK-" marks the origin, so worker K does not import its own input back.
                let name = format!("{:06}-w{}-{}", self.seq, k, base);
                self.seq += 1;
                let data = fs::read(&path)?;
                let tmp = self.sync_dir.join("shared").join(format!("{name}.tmp"));
                fs::write(&tmp, &data)?;
                fs::rename(&tmp, self.sync_dir.join("shared").join(&name))?;
                if let Some(c) = &self.corpus_dir {
                    fs::write(c.join(&name), &data)?;
                }
                self.published += 1;
                out.push(Published { name, worker: k, new_edges, new_pairs });
            }
        }
        Ok(out)
    }
}

/// A worker's `stats.json` (the fields the supervisor uses).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WorkerStats {
    #[serde(default)]
    pub worker_id: i64,
    #[serde(default)]
    pub elapsed_s: f64,
    #[serde(default)]
    pub execs: u64,
    #[serde(default)]
    pub execs_per_s: f64,
    #[serde(default)]
    pub corpus: u64,
    #[serde(default)]
    pub edges_covered: u64,
    #[serde(default)]
    pub edges_total: u64,
    #[serde(default)]
    pub crashes_unique: u64,
    #[serde(default)]
    pub timeouts: u64,
    #[serde(default)]
    pub done: bool,
}

/// One entry of a worker's `crashes.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerCrash {
    pub id: i64,
    pub kind: String,
    #[serde(default)]
    pub frames: Vec<String>,
    pub file: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub found_s: f64,
    #[serde(default)]
    pub hits: u64,
}

/// Crashes with the same signature from all workers, merged.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CrashGroup {
    pub kind: String,
    pub frames: Vec<String>,
    /// The earliest find: worker, its file, when (seconds since that worker started).
    pub first_worker: usize,
    pub file: String,
    pub size: u64,
    pub found_s: f64,
    pub hits: u64,
    pub workers: Vec<usize>,
}

pub fn read_worker_stats(worker_dir: &Path) -> Option<WorkerStats> {
    serde_json::from_str(&fs::read_to_string(worker_dir.join("stats.json")).ok()?).ok()
}

pub fn read_worker_crashes(worker_dir: &Path) -> Vec<WorkerCrash> {
    fs::read_to_string(worker_dir.join("crashes.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Merges the workers' crash lists by signature (kind + frames).
pub fn merge_crashes(per_worker: &[(usize, Vec<WorkerCrash>)]) -> Vec<CrashGroup> {
    let mut groups: BTreeMap<String, CrashGroup> = BTreeMap::new();
    for (k, list) in per_worker {
        for c in list {
            let key = format!("{} | {}", c.kind, c.frames.join(" | "));
            let g = groups.entry(key).or_insert_with(|| CrashGroup {
                kind: c.kind.clone(),
                frames: c.frames.clone(),
                first_worker: *k,
                file: c.file.clone(),
                size: c.size,
                found_s: c.found_s,
                hits: 0,
                workers: Vec::new(),
            });
            g.hits += c.hits;
            if !g.workers.contains(k) {
                g.workers.push(*k);
            }
            if c.found_s < g.found_s {
                g.found_s = c.found_s;
                g.first_worker = *k;
                g.file = c.file.clone();
                g.size = c.size;
            }
        }
    }
    let mut v: Vec<CrashGroup> = groups.into_values().collect();
    v.sort_by(|a, b| a.found_s.total_cmp(&b.found_s));
    v
}

/// Totals over the workers plus the global coverage.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub elapsed_s: f64,
    pub workers: usize,
    pub workers_done: usize,
    pub execs: u64,
    pub execs_per_s: f64,
    pub edges_global: usize,
    pub edges_total: u64,
    pub edges_best_worker: u64,
    pub corpus_global: usize,
    pub offered: usize,
    pub crashes_unique: usize,
    pub timeouts: u64,
}

pub fn summarize(stats: &[WorkerStats], curator: &Curator, crashes: usize, elapsed_s: f64) -> Summary {
    Summary {
        elapsed_s,
        workers: stats.len(),
        workers_done: stats.iter().filter(|s| s.done).count(),
        execs: stats.iter().map(|s| s.execs).sum(),
        execs_per_s: stats.iter().map(|s| s.execs_per_s).sum(),
        edges_global: curator.map.edges(),
        edges_total: stats.iter().map(|s| s.edges_total).max().unwrap_or(0),
        edges_best_worker: stats.iter().map(|s| s.edges_covered).max().unwrap_or(0),
        corpus_global: curator.published,
        offered: curator.offered,
        crashes_unique: crashes,
        timeouts: stats.iter().map(|s| s.timeouts).sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(edge: u32, bucket: u32) -> u32 {
        edge << 3 | bucket
    }

    #[test]
    fn global_map_counts_new_edges_and_buckets() {
        let mut m = GlobalMap::default();
        assert_eq!(m.merge(&[e(1, 0), e(2, 0)]), (2, 2));
        assert!(!m.is_new(&[e(1, 0)]));
        assert!(m.is_new(&[e(1, 3)]));
        assert_eq!(m.merge(&[e(1, 3), e(2, 0)]), (0, 1));
        assert_eq!(m.merge(&[e(9, 7)]), (1, 1));
        assert_eq!(m.edges(), 3);
    }

    #[test]
    fn parse_edges_rejects_garbage() {
        assert_eq!(parse_edges("8 17 \n 24"), Some(vec![8, 17, 24]));
        assert_eq!(parse_edges(""), Some(vec![]));
        assert_eq!(parse_edges("8 x"), None);
    }

    fn put(dir: &Path, worker: usize, name: &str, data: &[u8], edges: &[u32]) {
        let q = dir.join(format!("worker-{worker}")).join("queue");
        fs::create_dir_all(&q).unwrap();
        let text: Vec<String> = edges.iter().map(u32::to_string).collect();
        fs::write(q.join(format!("{name}.edges")), text.join(" ")).unwrap();
        fs::write(q.join(name), data).unwrap();
    }

    #[test]
    fn curator_publishes_only_globally_new_inputs() {
        let t = tempfile::tempdir().unwrap();
        let sync = t.path().join("sync");
        let corpus = t.path().join("corpus");
        let mut c = Curator::new(&sync, Some(&corpus)).unwrap();
        put(&sync, 0, "id-000000-seed", b"a", &[e(1, 0), e(2, 0)]);
        put(&sync, 1, "id-000000-seed", b"a", &[e(1, 0), e(2, 0)]);
        put(&sync, 1, "id-000001-havoc", b"b", &[e(1, 0), e(3, 0)]);
        let p = c.scan().unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].worker, 0);
        assert_eq!(p[1].worker, 1);
        assert_eq!(p[1].new_edges, 1);
        assert!(p[1].name.contains("-w1-"));
        assert_eq!(fs::read(sync.join("shared").join(&p[1].name)).unwrap(), b"b");
        assert_eq!(fs::read_dir(&corpus).unwrap().count(), 2);
        // Nothing is offered twice.
        assert!(c.scan().unwrap().is_empty());
        assert_eq!(c.offered, 3);
        // A new hit-count bucket of a known edge is new.
        put(&sync, 0, "id-000001-havoc", b"c", &[e(3, 4)]);
        assert_eq!(c.scan().unwrap().len(), 1);
    }

    #[test]
    fn curator_waits_for_the_sidecar() {
        let t = tempfile::tempdir().unwrap();
        let sync = t.path().join("sync");
        let mut c = Curator::new(&sync, None).unwrap();
        let q = sync.join("worker-0").join("queue");
        fs::create_dir_all(&q).unwrap();
        fs::write(q.join("id-000000-seed"), b"x").unwrap();
        assert!(c.scan().unwrap().is_empty());
        fs::write(q.join("id-000000-seed.edges"), "8").unwrap();
        assert_eq!(c.scan().unwrap().len(), 1);
    }

    fn crash(kind: &str, frame: &str, file: &str, found: f64, hits: u64) -> WorkerCrash {
        WorkerCrash { id: 0, kind: kind.into(), frames: vec![frame.into()], file: file.into(), size: 3, found_s: found, hits }
    }

    #[test]
    fn crashes_merge_by_signature_and_keep_the_earliest() {
        let g = merge_crashes(&[
            (0, vec![crash("heap-buffer-overflow READ", "f a.c:1", "c0", 5.0, 2), crash("SEGV", "g b.c:2", "c1", 9.0, 1)]),
            (1, vec![crash("heap-buffer-overflow READ", "f a.c:1", "c9", 2.0, 4)]),
        ]);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].kind, "heap-buffer-overflow READ");
        assert_eq!(g[0].first_worker, 1);
        assert_eq!(g[0].file, "c9");
        assert_eq!(g[0].hits, 6);
        assert_eq!(g[0].workers, vec![0, 1]);
        assert_eq!(g[1].found_s, 9.0);
    }

    #[test]
    fn worker_files_are_read_leniently() {
        let t = tempfile::tempdir().unwrap();
        assert!(read_worker_stats(t.path()).is_none());
        assert!(read_worker_crashes(t.path()).is_empty());
        fs::write(t.path().join("stats.json"), r#"{"execs": 10, "edges_covered": 4, "extra": "ignored"}"#).unwrap();
        let s = read_worker_stats(t.path()).unwrap();
        assert_eq!((s.execs, s.edges_covered), (10, 4));
        fs::write(t.path().join("crashes.json"), "[\n]\n").unwrap();
        assert!(read_worker_crashes(t.path()).is_empty());
    }
}
