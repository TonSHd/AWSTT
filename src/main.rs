use eframe::egui::{
    self, Align, Color32, Layout, Painter, Pos2, Rect, RichText, Rounding, Shape, Stroke, Vec2,
};
use egui_plot::{Bar, BarChart, Line, Plot, PlotPoints};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

const MAX_HISTORY:       usize = 512;
const WATERFALL_COLS:    usize = 120;
const WATERFALL_ROWS:    usize = 48;
const GRID_SIZE:         usize = 40;
const CELL_METERS:       f64   = 0.5;
const PATH_LOSS_N:       f64   = 2.7;
const RSSI_AT_1M_2G:     f64   = -40.0;
const RSSI_AT_1M_5G:     f64   = -45.0;
const WALL_ATTEN_DB:     f64   = 8.0;
const RMS_WINDOW:        usize = 4096;


#[derive(Clone, Copy, PartialEq)]
enum Tab { Monitor, Devices, Tests }
impl Tab {
    fn label(self) -> &'static str {
        match self { Self::Monitor => "Overview",
                     Self::Devices => "Device Map", Self::Tests => "Diagnostics" }
    }
}


#[derive(Clone, Copy, PartialEq)]
enum Waveform { Sine, Square, Saw, Triangle }
impl Waveform {
    fn label(self) -> &'static str { match self { Self::Sine=>"Sine",Self::Square=>"Square",Self::Saw=>"Saw",Self::Triangle=>"Triangle" } }
    fn sample(self, p: f64) -> f64 {
        let p = p.fract();
        match self {
            Self::Sine     => (std::f64::consts::TAU * p).sin(),
            Self::Square   => if p < 0.5 { 1.0 } else { -1.0 },
            Self::Saw      => 2.0 * p - 1.0,
            Self::Triangle => 1.0 - 4.0 * (p - 0.5).abs(),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Theme { Cyan, Green, Amber }
impl Theme {
    fn primary(self)   -> Color32 { match self { Self::Cyan=>Color32::from_rgb(0,220,255),   Self::Green=>Color32::from_rgb(0,255,140),   Self::Amber=>Color32::from_rgb(255,180,0) } }
    fn secondary(self) -> Color32 { match self { Self::Cyan=>Color32::from_rgb(0,140,200),   Self::Green=>Color32::from_rgb(0,180,100),   Self::Amber=>Color32::from_rgb(200,120,0) } }
    fn accent(self)    -> Color32 { match self { Self::Cyan=>Color32::from_rgb(255,80,120),  Self::Green=>Color32::from_rgb(80,120,255),  Self::Amber=>Color32::from_rgb(80,200,255) } }
    fn label(self)     -> &'static str { match self { Self::Cyan=>"Cyan",Self::Green=>"Green",Self::Amber=>"Amber" } }
}

#[derive(Clone, PartialEq)]
enum TestStatus { Idle, Running, Pass, Warn, Fail }


#[derive(Clone)]
struct Peer {
    ip:         String,
    mac:        String,
    host:       String,
    ping:       f64,
    rssi:       f64,
    dist:       f64,
    up:         bool,
    is_wifi:    bool,
    gx:         usize,
    gy:         usize,
}
impl Peer {
    fn new(ip: &str, mac: &str) -> Self {
        Self { ip: ip.into(), mac: mac.into(), host: "".into(),
               ping: 0.0, rssi: -200.0, dist: 10.0,
               up: false, is_wifi: false, gx: GRID_SIZE/2, gy: GRID_SIZE/2 }
    }
}

struct Peers {
    list:     Vec<Peer>,
    active:   bool,
    last:     Option<Instant>,
    log:      VecDeque<String>,
    cached:   HashMap<String, (f64, f64)>,
}
impl Peers {
    fn new() -> Self {
        Self { list: vec![], active: false, last: None, log: VecDeque::with_capacity(120), cached: HashMap::new() }
    }
    fn log(&mut self, s: &str) { if self.log.len()>=120{self.log.pop_front();} self.log.push_back(s.into()); }
}


#[derive(Clone)]
struct Check {
    name: String, target: String, unit: String,
    state: TestStatus, out: String, val: f64,
    history: VecDeque<f64>, warn: f64, fail: f64, high_is_good: bool,
}
impl Check {
    fn new(n:&str,t:&str,u:&str,w:f64,f:f64,h:bool)->Self {
        Self{name:n.into(),target:t.into(),unit:u.into(),
             state:TestStatus::Idle,out: "".into(),val:0.0,
             history:VecDeque::with_capacity(30),warn:w,fail:f,high_is_good:h}
    }
}

struct Checks {
    tasks:   Vec<Check>,
    log:     VecDeque<String>,
    busy:    bool,
}
impl Checks {
    fn new() -> Self {
        Self {
            tasks: vec![
                Check::new("PING GATEWAY","gateway",    "ms",   20.0,100.0, false),
                Check::new("PING 8.8.8.8","8.8.8.8",   "ms",   30.0,150.0, false),
                Check::new("PING 1.1.1.1","1.1.1.1",   "ms",   30.0,150.0, false),
                Check::new("DNS RESOLVE", "google.com", "ms",  100.0,500.0, false),
                Check::new("PKT LOSS",    "8.8.8.8",   "%",     5.0, 20.0, false),
                Check::new("JITTER",      "8.8.8.8",   "ms",   10.0, 50.0, false),
                Check::new("HTTP CHECK",  "gstatic",   "ms",  500.0,2000.0,false),
                Check::new("ROUTE HOPS",  "8.8.8.8",  "hops", 10.0, 20.0, false),
                Check::new("THROUGHPUT",  "LAN avg",  "MB/s",  0.0,  0.0,  true),
                Check::new("ERR RATE",    "iface",    "/s",   10.0,100.0,  false),
                Check::new("SIGNAL SCORE","composite","/100",  0.0,  0.0,  true),
                Check::new("MTU PROBE",   "gateway",  "bytes", 0.0,  0.0,  true),
            ],
            log: VecDeque::with_capacity(200), busy: false,
        }
    }
    fn log(&mut self, s: &str) { if self.log.len()>=200{self.log.pop_front();} self.log.push_back(s.into()); }
}


struct LiveStats {
    bps_h:  VecDeque<f64>,
    rssi_h: VecDeque<f64>,
    pps_h:  VecDeque<f64>,
    errs_h: VecDeque<f64>,
    db_h:   VecDeque<f64>,
    waves:  VecDeque<Vec<f32>>,
    now_bps:   f64,
    now_rssi:  f64,
    now_pps:   f64,
    now_errs:  f64,
    now_db:    f64,
    peak_bps:  f64,
    peak_rssi: f64,
    freq:      f64,
    amp:       f64,
}
impl Default for LiveStats {
    fn default() -> Self {
        Self {
            bps_h:VecDeque::with_capacity(MAX_HISTORY),rssi_h:VecDeque::with_capacity(MAX_HISTORY),
            pps_h:VecDeque::with_capacity(MAX_HISTORY),errs_h:VecDeque::with_capacity(MAX_HISTORY),
            db_h:VecDeque::with_capacity(MAX_HISTORY),
            waves:VecDeque::with_capacity(WATERFALL_ROWS),
            now_bps:0.0,now_rssi:-90.0,now_pps:0.0,now_errs:0.0,
            now_db:-80.0,peak_bps:0.0,peak_rssi:-90.0,
            freq:440.0,amp:0.0,
        }
    }
}

fn push_dq(dq: &mut VecDeque<f64>, v: f64) { dq.push_back(v); if dq.len()>MAX_HISTORY{dq.pop_front();} }

fn bps_to_rssi(bps: f64, err: f64) -> f64 {
    let n = (bps / 125_000_000.0).clamp(0.0, 1.0);
    (-90.0 + 70.0 * n - err * 30.0).clamp(-90.0, -20.0)
}


fn read_iface(iface: &str) -> Option<(u64,u64,u64,u64)> {
    let raw = fs::read_to_string("/proc/net/dev").ok()?;
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with(iface) {
            let f: Vec<u64> = t[iface.len()+1..].split_whitespace().filter_map(|s|s.parse().ok()).collect();
            if f.len()>=4 { return Some((f[0],f[1],f[2],f[3])); }
        }
    }
    None
}

fn get_gateway() -> Option<String> {
    let d = fs::read_to_string("/proc/net/route").ok()?;
    for line in d.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len()>=3 && f[1]=="00000000" {
            let gw = u32::from_str_radix(f[2],16).ok()?;
            return Some(format!("{}.{}.{}.{}",gw&0xFF,(gw>>8)&0xFF,(gw>>16)&0xFF,(gw>>24)&0xFF));
        }
    }
    None
}

fn list_interfaces() -> Vec<String> {
    let mut out: Vec<String> = vec![];
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n != "lo" { out.push(n); }
        }
    }
    out.sort();
    out
}

fn get_default_interface() -> Option<String> {
    let d = fs::read_to_string("/proc/net/route").ok()?;
    for line in d.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[1] == "00000000" {
            return Some(f[0].to_string());
        }
    }
    None
}

fn find_wifi_iface() -> Option<String> {
    if let Ok(o) = Command::new("iw").arg("dev").output() {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            let t = line.trim();
            if t.starts_with("Interface ") { return Some(t[10..].trim().to_string()); }
        }
    }
    if let Ok(e) = fs::read_dir("/sys/class/net") {
        for e in e.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("wl") { return Some(n); }
        }
    }
    None
}


fn rssi_to_distance(rssi: f64, freq_mhz: u32) -> f64 {
    let r0 = if freq_mhz>=5000 { RSSI_AT_1M_5G } else { RSSI_AT_1M_2G };
    10.0_f64.powf((r0 - rssi) / (10.0 * PATH_LOSS_N)).clamp(0.3, 60.0)
}


fn scan_arp_devices() -> Vec<Peer> {
    let mut devs: Vec<Peer> = vec![];
    if let Ok(data) = fs::read_to_string("/proc/net/arp") {
        for line in data.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len()>=4 && f[3]!="00:00:00:00:00:00" && f[2]!="0x0" {
                devs.push(Peer::new(f[0],f[3]));
            }
        }
    }
    if let Ok(out) = Command::new("ip").args(["neigh","show"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len()>=5 && f[3]=="lladdr" {
                let ip = f[0]; let mac = f[4];
                let state = f.last().copied().unwrap_or("");
                if state!="FAILED" && !devs.iter().any(|d|d.ip==ip) {
                    devs.push(Peer::new(ip,mac));
                }
            }
        }
    }
    devs
}

fn parse_ping_single(s: &str) -> f64 {
    s.lines().find(|l|l.contains("time="))
        .and_then(|l|l.find("time=").map(|p|&l[p+5..]))
        .and_then(|r|r.split_whitespace().next())
        .and_then(|v|v.parse().ok()).unwrap_or(0.0)
}

fn enrich_devices(devs: &mut Vec<Peer>, wifi: &Option<String>) {
    let mut wifi_rssi: std::collections::HashMap<String,f64> = Default::default();
    if let Some(ref iface) = wifi {
        if let Ok(out) = Command::new("iw").args(["dev",iface,"station","dump"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            let mut cur_mac = String::new();
            for line in s.lines() {
                let t = line.trim();
                if t.starts_with("Station ") { cur_mac = t.split_whitespace().nth(1).unwrap_or("").to_string(); }
                else if t.starts_with("signal:") && !cur_mac.is_empty() {
                    let sig = t.split(':').nth(1).and_then(|v|v.trim().split_whitespace().next()).and_then(|v|v.parse().ok()).unwrap_or(-100.0);
                    wifi_rssi.insert(cur_mac.to_lowercase(), sig);
                }
            }
        }
    }
    for dev in devs.iter_mut() {
        if let Ok(out) = Command::new("ping").args(["-c","1","-W","1",&dev.ip]).output() {
            dev.up = out.status.success();
            dev.ping = parse_ping_single(&String::from_utf8_lossy(&out.stdout));
        }
        let ml = dev.mac.to_lowercase();
        if let Some(&rssi) = wifi_rssi.get(&ml) {
            dev.rssi = rssi;
            dev.is_wifi  = true;
            dev.dist = rssi_to_distance(rssi, 2412);
        } else {
            dev.dist = if dev.ping<1.0{1.5} else if dev.ping<5.0{3.0+dev.ping} else{10.0+(dev.ping-5.0).min(40.0)};
        }
        if let Ok(out) = Command::new("host").args(["-W","1",&dev.ip]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(ptr) = s.lines().next().and_then(|l|l.split("pointer").nth(1)) {
                dev.host = ptr.trim().trim_end_matches('.').to_string();
            }
        }
    }
}

fn assign_device_positions(
    devs: &mut Vec<Peer>,
    router: (usize, usize),
    obstacles: &[bool],
    grid: &[f64],
    ) {
    let (cx, cy) = router;
    let n = devs.len().max(1);
    let scale = (GRID_SIZE as f64 / 2.0 - 3.0) / 20.0;

    for (i, dev) in devs.iter_mut().enumerate() {
        let preferred_angle = i as f64 * std::f64::consts::TAU / n as f64;
        let target_cells = (dev.dist * scale).clamp(2.0, GRID_SIZE as f64 / 2.0 - 2.0);

        let mut best = (9999.0, cx, cy);
        for y in 1..GRID_SIZE - 1 {
            for x in 1..GRID_SIZE - 1 {
                let idx = y * GRID_SIZE + x;
                if obstacles[idx] {
                    continue;
                }

                let dx = x as f64 - cx as f64;
                let dy = y as f64 - cy as f64;
                let d = (dx * dx + dy * dy).sqrt();
                if d < 0.2 {
                    continue;
                }

                let ring_err = (d - target_cells).abs();
                let angle = dy.atan2(dx);
                let mut aerr = (angle - preferred_angle).abs();
                if aerr > std::f64::consts::PI {
                    aerr = std::f64::consts::TAU - aerr;
                }
                let signal = grid.get(idx).copied().unwrap_or(0.0).clamp(0.0, 1.0);
                let sig_pen = if dev.is_wifi { (1.0 - signal) * 1.8 } else { signal * 0.4 };
                let score = ring_err + aerr * 0.35 + sig_pen;
                if score < best.0 {
                    best = (score, x, y);
                }
            }
        }
        dev.gx = best.1;
        dev.gy = best.2;
    }
    }


    fn obstacles_in_path(
obs: &[bool], x0:usize, y0:usize, x1:usize, y1:usize) -> usize {
    let(mut x,mut y)=(x0 as i32, y0 as i32);
    let(dx,dy)=((x1 as i32-x0 as i32).abs(),(y1 as i32-y0 as i32).abs());
    let(sx,sy)=(if x<x1 as i32{1}else{-1},if y<y1 as i32{1}else{-1});
    let mut err=dx-dy; let mut count=0;
    loop {
        if x==x1 as i32&&y==y1 as i32{break;}
        if x>=0&&x<GRID_SIZE as i32&&y>=0&&y<GRID_SIZE as i32 { if obs[y as usize*GRID_SIZE+x as usize]{count+=1;} }
        let e2=2*err;
        if e2>-dy{err-=dy;x+=sx;}
        if e2<dx {err+=dx;y+=sy;}
    }
    count
}


fn parse_ping_out(s: &str) -> (f64,f64,f64,f64) {
    let(mut min,mut avg,mut max,mut loss)=(9999.0,9999.0,0.0,100.0);
    for line in s.lines() {
        if line.contains("packet loss") {
            if let Some(p)=line.find('%'){
                let st=line[..p].rfind(|c:char|!c.is_ascii_digit()&&c!='.').map(|i|i+1).unwrap_or(0);
                if let Ok(v)=line[st..p].parse::<f64>(){loss=v;}
            }
        }
        if line.contains("rtt")||line.contains("round-trip") {
            if let Some(eq)=line.find('=') {
                let p:Vec<&str>=line[eq+1..].trim().split('/').collect();
                if p.len()>=3{min=p[0].trim().parse().unwrap_or(9999.0);avg=p[1].trim().parse().unwrap_or(9999.0);max=p[2].trim().parse().unwrap_or(0.0);}
            }
        }
    }
    (min,avg,max,loss)
}

fn extract_json_number(json: &str, marker: &str) -> Option<f64> {
    let p = json.find(marker)?;
    let mut tail = &json[p + marker.len()..];
    tail = tail.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '"' || c == '{' || c == '[');
    let mut end = 0usize;
    for (i, ch) in tail.char_indices() {
        if ch.is_ascii_digit() || ch == '.' || ch == '-' {
            end = i + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 { return None; }
    tail[..end].parse::<f64>().ok()
}

fn run_speedtest_net() -> Option<(f64, f64, String)> {
    let cmds = [
        ("speedtest", vec!["--json"]),
        ("speedtest-cli", vec!["--json"]),
    ];
    for (cmd, args) in cmds {
        if let Ok(out) = Command::new(cmd).args(&args).output() {
            if out.status.success() {
                if let Ok(raw) = String::from_utf8(out.stdout) {
                    let d = extract_json_number(&raw, "\"download\":")
                        .or_else(|| extract_json_number(&raw, "\"download\":{\"bandwidth\":"))
                        .or_else(|| extract_json_number(&raw, "\"downloadBandwidth\":"));
                    let u = extract_json_number(&raw, "\"upload\":")
                        .or_else(|| extract_json_number(&raw, "\"upload\":{\"bandwidth\":"))
                        .or_else(|| extract_json_number(&raw, "\"uploadBandwidth\":"));
                    if let (Some(down), Some(up)) = (d, u) {
                        let div = if down > 100000.0 { 125_000.0 } else { 1_000_000.0 };
                        return Some((down / div, up / div, format!("via {}", cmd)));
                    }
                }
            }
        }
    }
    None
}

fn run_real_download_test() -> (f64, String) {
    if let Some((down, _, src)) = run_speedtest_net() {
        return (down, format!("{:.1} Mbps ({})", down, src));
    }
    let url = "https://speed.cloudflare.com/__down?bytes=100000000";
    let start = Instant::now();
    let mut jobs = vec![];
    for _ in 0..4 {
        jobs.push(thread::spawn(move || {
            Command::new("curl")
                .args(["-s", "-L", "-o", "/dev/null", "--max-time", "30", "-w", "%{size_download}", url])
                .output()
                .ok()
                .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<f64>().ok())
                .unwrap_or(0.0)
        }));
    }
    let total: f64 = jobs.into_iter().map(|j| j.join().unwrap_or(0.0)).sum();
    let took = start.elapsed().as_secs_f64();
    if total < 1000.0 { return (0.0, "primary tool failed, fallback unreachable".into()); }
    let rate = (total * 8.0 / took) / 1_000_000.0;
    (rate, format!("{:.1} Mbps (parallel streams)", rate))
}

fn run_real_upload_test() -> (f64, String) {
    if let Some((_, up, src)) = run_speedtest_net() {
        return (up, format!("{:.1} Mbps ({})", up, src));
    }
    let start = Instant::now();
    let mut jobs = vec![];
    for _ in 0..4 {
        jobs.push(thread::spawn(move || {
            Command::new("sh").args(["-c",
                "dd if=/dev/urandom bs=1M count=100 2>/dev/null | curl -s -o /dev/null --max-time 30 -w '%{size_upload}' -X POST --data-binary @- https://speed.cloudflare.com/__up"
            ]).output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<f64>().ok()).unwrap_or(0.0)
        }));
    }
    let total: f64 = jobs.into_iter().map(|j| j.join().unwrap_or(0.0)).sum();
    let took = start.elapsed().as_secs_f64();
    if total < 1000.0 { return (0.0, "upload failed (speedtest.net tool missing?)".into()); }
    let rate = (total * 8.0 / took) / 1_000_000.0;
    (rate, format!("{:.1} Mbps (parallel fallback)", rate))
}


fn run_test_entry(entry: Check, sig: (f64,f64)) -> (TestStatus,f64,String) {
    let (bps_avg, errs_avg) = sig;
    match entry.name.as_str() {
        "PING GATEWAY" => {
            let gw=get_gateway().unwrap_or_else(||"192.168.1.1".to_string());
            match Command::new("ping").args(["-c","5","-W","2","-i","0.2",&gw]).output(){
                Ok(o)=>{let s=String::from_utf8_lossy(&o.stdout);let(_,avg,_,loss)=parse_ping_out(&s);
                    if loss>entry.fail{(TestStatus::Fail,avg,format!("{:.1}ms {:.0}% loss",avg,loss))}
                    else if avg>entry.warn{(TestStatus::Warn,avg,format!("{:.1}ms",avg))}
                    else{(TestStatus::Pass,avg,format!("{:.1}ms gw={}",avg,gw))}}
                Err(e)=>(TestStatus::Fail,9999.0,e.to_string()),
            }
        }
        "PING 8.8.8.8"|"PING 1.1.1.1" => {
            let host=if entry.name.contains("1.1.1"){"1.1.1.1"}else{"8.8.8.8"};
            match Command::new("ping").args(["-c","5","-W","2","-i","0.2",host]).output(){
                Ok(o)=>{let s=String::from_utf8_lossy(&o.stdout);let(_,avg,_,loss)=parse_ping_out(&s);
                    if loss>entry.fail{(TestStatus::Fail,avg,format!("{:.1}ms {:.0}%loss",avg,loss))}
                    else if avg>entry.warn{(TestStatus::Warn,avg,format!("{:.1}ms",avg))}
                    else{(TestStatus::Pass,avg,format!("{:.1}ms",avg))}}
                Err(e)=>(TestStatus::Fail,9999.0,e.to_string()),
            }
        }
        "DNS RESOLVE" => {
            let t=Instant::now();
            let ok=Command::new("host").args(["-W","3","google.com"]).output().map(|o|o.status.success()).unwrap_or(false);
            let ms=t.elapsed().as_secs_f64()*1000.0;
            if !ok{(TestStatus::Fail,ms,"resolution failed".to_string())}
            else if ms>entry.fail{(TestStatus::Fail,ms,format!("{:.0}ms",ms))}
            else if ms>entry.warn{(TestStatus::Warn,ms,format!("{:.0}ms",ms))}
            else{(TestStatus::Pass,ms,format!("{:.0}ms",ms))}
        }
        "PKT LOSS" => {
            match Command::new("ping").args(["-c","20","-W","2","-i","0.1","8.8.8.8"]).output(){
                Ok(o)=>{let s=String::from_utf8_lossy(&o.stdout);let(_,_,_,loss)=parse_ping_out(&s);
                    if loss>entry.fail{(TestStatus::Fail,loss,format!("{:.1}%",loss))}
                    else if loss>entry.warn{(TestStatus::Warn,loss,format!("{:.1}%",loss))}
                    else{(TestStatus::Pass,loss,format!("{:.1}%",loss))}}
                Err(e)=>(TestStatus::Fail,100.0,e.to_string()),
            }
        }
        "JITTER" => {
            match Command::new("ping").args(["-c","20","-W","2","-i","0.1","8.8.8.8"]).output(){
                Ok(o)=>{
                    let s=String::from_utf8_lossy(&o.stdout);
                    let jitter=s.lines().find(|l|l.contains("rtt")||l.contains("round-trip"))
                        .and_then(|l|l.find('=').map(|eq|&l[eq+1..]))
                        .and_then(|r|r.trim().split('/').nth(3))
                        .and_then(|v|v.split_whitespace().next()).and_then(|v|v.parse::<f64>().ok()).unwrap_or(0.0);
                    if jitter>entry.fail{(TestStatus::Fail,jitter,format!("{:.2}ms mdev",jitter))}
                    else if jitter>entry.warn{(TestStatus::Warn,jitter,format!("{:.2}ms mdev",jitter))}
                    else{(TestStatus::Pass,jitter,format!("{:.2}ms mdev",jitter))}}
                Err(e)=>(TestStatus::Fail,9999.0,e.to_string()),
            }
        }
        "HTTP CHECK" => {
            let t=Instant::now();
            let ok=Command::new("curl").args(["-s","-o","/dev/null","--max-time","4","-w","%{http_code}","http://connectivitycheck.gstatic.com/generate_204"])
                .output().map(|o|String::from_utf8_lossy(&o.stdout).trim()=="204").unwrap_or(false);
            let ms=t.elapsed().as_secs_f64()*1000.0;
            if !ok{(TestStatus::Fail,ms,"no 204".to_string())} else if ms>entry.fail{(TestStatus::Warn,ms,format!("{:.0}ms",ms))} else{(TestStatus::Pass,ms,format!("{:.0}ms",ms))}
        }
        "ROUTE HOPS" => {
            let hops=Command::new("tracepath").args(["-n","-m","20","8.8.8.8"]).output()
                .map(|o|String::from_utf8_lossy(&o.stdout).lines().filter(|l|l.trim().starts_with(|c:char|c.is_ascii_digit())).count() as f64).unwrap_or(0.0);
            if hops>entry.fail{(TestStatus::Warn,hops,format!("{:.0} hops",hops))} else{(TestStatus::Pass,hops,format!("{:.0} hops",hops))}
        }
        "THROUGHPUT" => {
            let mb=bps_avg/1e6;
            if mb>1.0{(TestStatus::Pass,mb,format!("{:.2} MB/s",mb))} else{(TestStatus::Warn,mb,format!("{:.3} MB/s",mb))}
        }
        "ERR RATE" => {
            if errs_avg>entry.fail{(TestStatus::Fail,errs_avg,format!("{:.1}/s",errs_avg))}
            else if errs_avg>entry.warn{(TestStatus::Warn,errs_avg,format!("{:.1}/s",errs_avg))}
            else{(TestStatus::Pass,errs_avg,format!("{:.2}/s",errs_avg))}
        }
        "SIGNAL SCORE" => {
            match Command::new("ping").args(["-c","5","-W","2","-i","0.2","8.8.8.8"]).output(){
                Ok(o)=>{
                    let s=String::from_utf8_lossy(&o.stdout);let(_,avg,_,loss)=parse_ping_out(&s);
                    let score=((100.0-(avg/2.0).min(100.0))*0.4+(100.0-loss*5.0).max(0.0)*0.4+(100.0-(errs_avg*2.0).min(100.0))*0.2).clamp(0.0,100.0);
                    if score<50.0{(TestStatus::Fail,score,format!("{:.0}/100",score))}
                    else if score<80.0{(TestStatus::Warn,score,format!("{:.0}/100",score))}
                    else{(TestStatus::Pass,score,format!("{:.0}/100",score))}}
                Err(_)=>(TestStatus::Fail,0.0,"ping failed".to_string()),
            }
        }
        "MTU PROBE" => {
            let gw=get_gateway().unwrap_or_else(||"192.168.1.1".to_string());
            let(mut lo,mut hi)=(576u32,1500u32);
            while hi-lo>8 {
                let mid=(lo+hi)/2;
                let ok=Command::new("ping").args(["-c","1","-W","1","-M","do","-s",&(mid-28).to_string(),&gw]).output().map(|o|o.status.success()).unwrap_or(false);
                if ok{lo=mid;}else{hi=mid-1;}
            }
            (TestStatus::Pass,lo as f64,format!("{} bytes",lo))
        }
        _=>(TestStatus::Idle,0.0,String::new()),
    }
}


fn spawn_network_thread(data: Arc<Mutex<LiveStats>>, speed: Arc<Mutex<f32>>, iface_ref: Arc<Mutex<String>>) {
    thread::spawn(move||{
        let mut prev=(0u64,0u64,0u64,0u64); let mut prev_t=Instant::now();
        let mut wf_acc:Vec<f64>=vec![]; let mut wf_tick=0u32; let mut first=true;
        let mut last_iface=String::new();
        loop {
            let sp=*speed.lock();
            let iface=iface_ref.lock().clone();
            if iface!=last_iface { first=true; prev=(0,0,0,0); last_iface=iface.clone(); }
            thread::sleep(Duration::from_millis((100.0/sp) as u64));
            let now=Instant::now(); let dt=now.duration_since(prev_t).as_secs_f64().max(0.001); prev_t=now;
            if let Some((bytes,pkts,errs,drops))=read_iface(&iface) {
                if first{prev=(bytes,pkts,errs,drops);first=false;continue;}
                let db=bytes.saturating_sub(prev.0) as f64/dt; let dp=pkts.saturating_sub(prev.1) as f64/dt;
                let de=errs.saturating_sub(prev.2) as f64/dt; let dd=drops.saturating_sub(prev.3) as f64/dt;
                let rssi=bps_to_rssi(db,if dp>0.0{de/dp}else{0.0});
                let norm=(db/125_000_000.0).clamp(0.0,1.0);
                wf_acc.push(norm); wf_tick+=1;
                if wf_tick>=(10.0/sp).max(1.0) as u32 {
                    wf_tick=0;
                    let last=wf_acc.last().copied().unwrap_or(0.0);
                    let col:Vec<f32>=(0..WATERFALL_COLS).map(|i|{let t=i as f64/WATERFALL_COLS as f64;let h=(last*(i+1) as f64*2.0*std::f64::consts::PI/WATERFALL_COLS as f64).sin().abs();(last*(0.5+0.5*h)*(1.0-t*0.3)).clamp(0.0,1.0) as f32}).collect();
                    let mut d=data.lock(); d.waves.push_front(col); if d.waves.len()>WATERFALL_ROWS{d.waves.pop_back();}
                    wf_acc.clear();
                }
                let mut d=data.lock();
                push_dq(&mut d.bps_h,db);push_dq(&mut d.rssi_h,rssi);push_dq(&mut d.pps_h,dp);push_dq(&mut d.errs_h,de+dd);
                d.now_bps=db;d.now_rssi=rssi;d.now_pps=dp;d.now_errs=de;
                if db>d.peak_bps{d.peak_bps=db;}if rssi>d.peak_rssi{d.peak_rssi=rssi;}
                d.freq=80.0+norm*1920.0; d.amp=0.3+norm*0.65;
                prev=(bytes,pkts,errs,drops);
            }
        }
    });
}

fn spawn_device_thread(
    devices:  Arc<Mutex<Peers>>,
    trigger:  Arc<AtomicBool>,
    wifi_iface: Option<String>,
    map_enabled: Arc<AtomicBool>,
) {
    thread::spawn(move||{
        let mut last=Instant::now()-Duration::from_secs(7);
        loop {
            thread::sleep(Duration::from_millis(900));
            let forced=trigger.swap(false,Ordering::Relaxed);
            if !map_enabled.load(Ordering::Relaxed) && !forced { continue; }
            if !forced && last.elapsed()<Duration::from_secs(6) { continue; }
            last=Instant::now();
            {let mut d=devices.lock(); d.active=true; d.log("scanning...");}
            let mut devs=scan_arp_devices();
            if let Some(gw)=get_gateway() {
                if !devs.iter().any(|d| d.ip==gw) { devs.push(Peer::new(&gw,"gw:gw:gw:gw:gw:gw")); }
            }
            devs.sort_by(|a,b| a.ip.cmp(&b.ip));
            devs.dedup_by(|a,b| a.ip==b.ip);
            {devices.lock().log(&format!("Detected devices: {}",devs.len()));}
            enrich_devices(&mut devs,&wifi_iface);
            
            let router = (GRID_SIZE/2, GRID_SIZE/2);
            let obstacles = vec![false; GRID_SIZE * GRID_SIZE];
            let grid = vec![0.0; GRID_SIZE * GRID_SIZE];
            
            assign_device_positions(&mut devs, router, &obstacles, &grid);
            {
                let mut d=devices.lock();
                for dev in devs.iter_mut() {
                    let key = if dev.mac.is_empty() { dev.ip.clone() } else { dev.mac.clone() };
                    let target = (dev.gx as f64, dev.gy as f64);
                    let smoothed = if let Some(prev) = d.cached.get(&key).copied() {
                        (prev.0 * 0.65 + target.0 * 0.35, prev.1 * 0.65 + target.1 * 0.35)
                    } else {
                        target
                    };
                    dev.gx = smoothed.0.round().clamp(1.0, (GRID_SIZE-2) as f64) as usize;
                    dev.gy = smoothed.1.round().clamp(1.0, (GRID_SIZE-2) as f64) as usize;
                    d.cached.insert(key, smoothed);
                }
                d.list=devs;
                d.active=false;
                d.last=Some(Instant::now());
                d.log("done");
            }
        }
    });
}


struct AudioStream { _s: cpal::Stream }

fn pick_output_device(host: &cpal::Host) -> Option<(cpal::Device, String)> {
    let mut any: Option<(cpal::Device,String)> = None;
    if let Ok(devs) = host.output_devices() {
        for dev in devs {
            if dev.default_output_config().is_err() { continue; }
            let name = dev.name().unwrap_or_default();
            if any.is_none() { any = Some((dev,name)); }
        }
    }
    if let Some(dev) = host.default_output_device() {
        if dev.default_output_config().is_ok() {
            let name = dev.name().unwrap_or_else(|_| "Default".into());
            return Some((dev, name));
        }
    }
    any
}

fn build_audio(
    data: Arc<Mutex<LiveStats>>, active: Arc<AtomicBool>,
    waveform: Arc<Mutex<Waveform>>, gain_db: Arc<Mutex<f32>>,
) -> Option<(AudioStream, String)> {
    let host = cpal::default_host();
    let (device, name) = pick_output_device(&host)?;
    let supported = device.default_output_config().ok()?;
    let rate = if supported.sample_rate().0==48000{48000}else{supported.sample_rate().0};
    let cfg = cpal::StreamConfig { channels:2, sample_rate:cpal::SampleRate(rate), buffer_size:cpal::BufferSize::Default };
    let sr = cfg.sample_rate.0 as f64;
    let ch = cfg.channels as usize;
    let mut phase=0.0f64; let mut cf=440.0f64; let mut ca=0.0f64;
    let mut rms_buf: Vec<f32> = Vec::with_capacity(RMS_WINDOW);

    let stream = device.build_output_stream(&cfg, move |out: &mut [f32], _| {
        if !active.load(Ordering::Relaxed) { out.fill(0.0); return; }
        let (tf,ta)={let d=data.lock();(d.freq,d.amp)};
        let wf=*waveform.lock();
        let gain=10.0f64.powf(*gain_db.lock() as f64/20.0);
        let frames=out.len()/ch;
        for f in 0..frames {
            cf+=(tf-cf)*0.003; ca+=(ta-ca)*0.003;
            phase+=cf/sr; if phase>=1.0{phase-=1.0;}
            let raw=wf.sample(phase)+0.15*wf.sample(phase*2.0)+0.07*wf.sample(phase*3.0);
            let s=(raw*ca*gain).clamp(-1.0,1.0) as f32;
            rms_buf.push(s);
            if rms_buf.len()>=RMS_WINDOW {
                let rms=(rms_buf.iter().map(|&x|(x as f64).powi(2)).sum::<f64>()/rms_buf.len() as f64).sqrt();
                let db=if rms>1e-10{20.0*rms.log10()}else{-80.0};
                let mut d=data.lock(); push_dq(&mut d.db_h,db); d.now_db=db;
                rms_buf.clear();
            }
            for c in 0..ch { out[f*ch+c]=s; }
        }
    }, |e|eprintln!("[audio] {e}"), None).ok()?;
    stream.play().ok()?;
    Some((AudioStream{_s:stream}, name))
}


struct App {
    data:          Arc<Mutex<LiveStats>>,
    devices:       Arc<Mutex<Peers>>,
    tests:         Arc<Mutex<Checks>>,
    sound_active:  Arc<AtomicBool>,
    waveform:      Arc<Mutex<Waveform>>,
    gain_db:       Arc<Mutex<f32>>,
    speed:         Arc<Mutex<f32>>,
    dev_trigger:   Arc<AtomicBool>,
    map_enabled:   Arc<AtomicBool>,
    selected_iface:  Arc<Mutex<String>>,
    available_ifaces: Vec<String>,
    _audio:        Option<AudioStream>,
    device_name:   String,
    selected_assoc_ip: Option<String>,
    tab:           Tab,
    theme:         Theme,
    frozen:        bool,
    show_peaks:    bool,
    log_scale:     bool,
    smoothing:     bool,
    snap_bps:  Vec<f64>,snap_rssi:Vec<f64>,snap_pps:Vec<f64>,snap_errs:Vec<f64>,snap_db:Vec<f64>,
    uptime:        Instant,
}

impl App {
    fn new(cc: &eframe::CreationContext, data: Arc<Mutex<LiveStats>>) -> Self {
        let mut vis=cc.egui_ctx.style().visuals.clone();
        vis.dark_mode=true; vis.panel_fill=Color32::from_rgb(8,11,18); vis.window_fill=Color32::from_rgb(8,11,18);
        vis.extreme_bg_color=Color32::from_rgb(5,7,12); vis.window_stroke=Stroke::new(1.0,Color32::from_rgb(26,38,60));
        vis.widgets.inactive.bg_fill=Color32::from_rgb(15,20,31); vis.widgets.hovered.bg_fill=Color32::from_rgb(24,33,52);
        vis.widgets.active.bg_fill=Color32::from_rgb(0,96,136); vis.widgets.noninteractive.bg_fill=Color32::from_rgb(10,14,22);
        vis.widgets.inactive.rounding=Rounding::same(5.0); vis.widgets.hovered.rounding=Rounding::same(5.0);
        vis.widgets.active.rounding=Rounding::same(5.0); vis.widgets.noninteractive.rounding=Rounding::same(5.0);
        let mut style=(*cc.egui_ctx.style()).clone(); style.visuals=vis;
        style.spacing.item_spacing=Vec2::new(6.0,5.0); style.spacing.button_padding=Vec2::new(11.0,6.0);
        cc.egui_ctx.set_style(style);

        let available_ifaces = list_interfaces();
        let default_iface = get_default_interface().or_else(|| available_ifaces.first().cloned()).unwrap_or_else(|| "eth0".to_string());
        let selected_iface = Arc::new(Mutex::new(default_iface));

        let sound_active=Arc::new(AtomicBool::new(false));
        let waveform=Arc::new(Mutex::new(Waveform::Sine));
        let gain_db=Arc::new(Mutex::new(3.0f32));
        let speed=Arc::new(Mutex::new(1.0f32));
        let dev_trigger=Arc::new(AtomicBool::new(false));
        let map_enabled=Arc::new(AtomicBool::new(true));
        let devices=Arc::new(Mutex::new(Peers::new()));
        let tests=Arc::new(Mutex::new(Checks::new()));

        spawn_network_thread(data.clone(), speed.clone(), selected_iface.clone());
        let wifi=find_wifi_iface();
        spawn_device_thread(devices.clone(), dev_trigger.clone(), wifi, map_enabled.clone());

        let audio=None;
        let dev_name="Not initialized".to_string();

        Self {
            data,devices,tests,sound_active,waveform,gain_db,speed,dev_trigger,map_enabled,
            selected_iface, available_ifaces,
            _audio:audio,device_name:dev_name,
            selected_assoc_ip:None,
            tab:Tab::Monitor,theme:Theme::Cyan,frozen:false,show_peaks:true,log_scale:false,smoothing:false,
            snap_bps:vec![],snap_rssi:vec![],snap_pps:vec![],snap_errs:vec![],snap_db:vec![],
            uptime:Instant::now(),
        }
    }

    fn get_series(&self) -> (Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>,Vec<f64>) {
        if self.frozen { return (self.snap_bps.clone(),self.snap_rssi.clone(),self.snap_pps.clone(),self.snap_errs.clone(),self.snap_db.clone()); }
        let d=self.data.lock();
        let sm=|v:&VecDeque<f64>|->Vec<f64>{
            if !self.smoothing{return v.iter().copied().collect();}
            v.iter().enumerate().map(|(i,_)|{let lo=i.saturating_sub(3);let hi=(i+4).min(v.len());v.range(lo..hi).sum::<f64>()/(hi-lo) as f64}).collect()
        };
        (sm(&d.bps_h),sm(&d.rssi_h),sm(&d.pps_h),sm(&d.errs_h),sm(&d.db_h))
    }
    fn is_wifi_selected(&self) -> bool {
        self.selected_iface.lock().starts_with("wl")
    }
}


fn card(ui: &mut egui::Ui, border: Color32, f: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none().fill(Color32::from_rgb(9,13,21)).rounding(Rounding::same(6.0))
        .stroke(Stroke::new(1.0,border)).inner_margin(egui::Margin::same(10.0)).show(ui,f);
}
fn section(ui: &mut egui::Ui, t: &str) { ui.label(RichText::new(t).size(10.0).color(Color32::from_rgb(112,136,171)).strong()); ui.add_space(4.0); }
fn pill(ui: &mut egui::Ui, label: &str, on: bool, pri: Color32) -> bool {
    let f=if on{pri.linear_multiply(0.2)}else{Color32::from_rgb(12,16,25)};
    let s=if on{Stroke::new(1.3,pri)}else{Stroke::new(1.0,Color32::from_rgb(32,42,62))};
    let t=if on{pri}else{Color32::from_rgb(112,129,161)};
    ui.add(egui::Button::new(RichText::new(label).size(11.0).color(t)).fill(f).stroke(s).rounding(Rounding::same(5.0)).min_size(Vec2::new(52.0,26.0))).clicked()
}
fn big_btn(ui: &mut egui::Ui, label: &str, on: bool, pri: Color32, acc: Color32) -> bool {
    let f=if on{pri.linear_multiply(0.17)}else{Color32::from_rgb(12,16,25)};
    let s=if on{Stroke::new(1.4,pri)}else{Stroke::new(1.0,Color32::from_rgb(32,42,62))};
    let t=if on{pri}else{acc};
    let w=ui.available_width();
    ui.add_sized(Vec2::new(w,34.0),egui::Button::new(RichText::new(label).size(12.0).color(t).strong()).fill(f).stroke(s).rounding(Rounding::same(6.0))).clicked()
}
fn stat_tile(ui: &mut egui::Ui, label: &str, val: &str, sub: &str, col: Color32) {
    egui::Frame::none().fill(Color32::from_rgb(7,9,15)).stroke(Stroke::new(1.0,col.linear_multiply(0.28))).rounding(Rounding::same(3.0)).inner_margin(egui::Margin::symmetric(10.0,6.0)).show(ui,|ui|{
        ui.set_min_width(88.0);
        ui.label(RichText::new(label).size(9.0).monospace().color(Color32::from_rgb(60,78,104)));
        ui.label(RichText::new(val).size(16.0).monospace().color(col).strong());
        if !sub.is_empty(){ui.label(RichText::new(sub).size(9.0).monospace().color(Color32::from_rgb(50,66,88)));}
    });
}
fn bar_meter(ui: &mut egui::Ui, val: f64, lo: f64, hi: f64, col: Color32, h: f32, is_rssi_lan: bool) {
    let(rect,_)=ui.allocate_exact_size(Vec2::new(ui.available_width(),h),egui::Sense::hover());
    let p=ui.painter_at(rect);
    p.rect_filled(rect,Rounding::same(2.0),Color32::from_rgb(7,9,14));
    if is_rssi_lan {
        p.text(rect.center(), egui::Align2::CENTER_CENTER, "RSSI is not for LAN", egui::FontId::monospace(9.0), Color32::from_rgb(80, 96, 120));
    } else {
        let norm=((val-lo)/(hi-lo)).clamp(0.0,1.0) as f32;
        if norm>0.001{let fill=Rect::from_min_max(rect.min,Pos2::new(rect.min.x+rect.width()*norm,rect.max.y));p.rect_filled(fill,Rounding::same(2.0),col.linear_multiply(0.55));}
        for t in 1..10{let x=rect.min.x+rect.width()*t as f32/10.0;p.line_segment([Pos2::new(x,rect.max.y-4.0),Pos2::new(x,rect.max.y)],Stroke::new(1.0,Color32::from_rgb(22,30,44)));}
    }
    p.rect_stroke(rect,Rounding::same(2.0),Stroke::new(1.0,col.linear_multiply(0.3)));
}
fn line_chart(ui: &mut egui::Ui, id: &str, title: &str, data: &[f64], col: Color32, h: f32, ylo: f64, yhi: Option<f64>, log: bool) {
    ui.label(RichText::new(title).size(10.0).monospace().color(Color32::from_rgb(85,106,138)));
    let pts:PlotPoints=data.iter().enumerate().map(|(i,&v)|{let y=if log&&v>0.0{v.log10()}else{v};[i as f64,y]}).collect();
    let y0=if log&&ylo>0.0{ylo.log10()}else{ylo};
    let mut p=Plot::new(id).height(h).show_axes([false,true]).show_grid(true).allow_zoom(false).allow_drag(false).allow_scroll(false).include_y(y0);
    if let Some(hi)=yhi{p=p.include_y(if log&&hi>0.0{hi.log10()}else{hi});} if data.is_empty(){p=p.include_y(0.0);}
    p.show(ui,|pu|{pu.line(Line::new(pts).color(col).width(1.8));});
}
fn dual_line_chart(ui: &mut egui::Ui, id: &str, title: &str, a: &[f64], ca: Color32, b: &[f64], cb: Color32, h: f32) {
    ui.label(RichText::new(title).size(10.0).monospace().color(Color32::from_rgb(85,106,138)));
    let pa:PlotPoints=a.iter().enumerate().map(|(i,&v)|[i as f64,v]).collect();
    let pb:PlotPoints=b.iter().enumerate().map(|(i,&v)|[i as f64,v]).collect();
    Plot::new(id).height(h).show_axes([false,true]).show_grid(true).allow_zoom(false).allow_drag(false).allow_scroll(false).include_y(0.0)
        .show(ui,|pu|{pu.line(Line::new(pa).color(ca).width(1.8));pu.line(Line::new(pb).color(cb).width(1.4));});
}
fn bar_chart(ui: &mut egui::Ui, id: &str, data: &[f64], col: Color32, h: f32) {
    let bars:Vec<Bar>=data.iter().enumerate().map(|(i,&v)| {
        let val = (v + 100.0).max(0.0);
        Bar::new(i as f64, val).width(1.0).fill(col.linear_multiply(0.65))
    }).collect();
    Plot::new(id).height(h).show_axes([false,true]).show_grid(true).allow_zoom(false).allow_drag(false).allow_scroll(false).include_y(0.0).include_y(100.0)
        .show(ui,|pu|{pu.bar_chart(BarChart::new(bars).color(col));});
}
fn fmt_bps(b:f64)->String{if b>=1e9{format!("{:.2}G/s",b/1e9)}else if b>=1e6{format!("{:.1}M/s",b/1e6)}else if b>=1e3{format!("{:.0}K/s",b/1e3)}else{format!("{:.0}B/s",b)}}
fn fmt_up(d:Duration)->String{let s=d.as_secs();format!("{:02}:{:02}:{:02}",s/3600,(s%3600)/60,s%60)}

fn iso_pt(gx:f32,gy:f32,gz:f32,origin:Pos2,cw:f32,ch:f32)->Pos2 {
    Pos2::new(origin.x+(gx-gy)*cw*0.5, origin.y+(gx+gy)*ch*0.5-gz*ch)
}
fn paint_floor(p:&Painter,gx:f32,gy:f32,origin:Pos2,cw:f32,ch:f32,col:Color32){
    let pts=vec![iso_pt(gx+0.5,gy,    0.0,origin,cw,ch),iso_pt(gx+1.0,gy+0.5,0.0,origin,cw,ch),
                 iso_pt(gx+0.5,gy+1.0,0.0,origin,cw,ch),iso_pt(gx,    gy+0.5,0.0,origin,cw,ch)];
    p.add(Shape::convex_polygon(pts,col,Stroke::NONE));
}
fn paint_block(p:&Painter,gx:f32,gy:f32,h:f32,origin:Pos2,cw:f32,ch:f32,col:Color32){
    let h=h.max(0.01);
    let top=vec![iso_pt(gx+0.5,gy,    h,origin,cw,ch),iso_pt(gx+1.0,gy+0.5,h,origin,cw,ch),
                 iso_pt(gx+0.5,gy+1.0,h,origin,cw,ch),iso_pt(gx,    gy+0.5,h,origin,cw,ch)];
    p.add(Shape::convex_polygon(top,col,Stroke::NONE));
    let left=vec![iso_pt(gx,gy+0.5,h,origin,cw,ch),iso_pt(gx+0.5,gy+1.0,h,origin,cw,ch),
                  iso_pt(gx+0.5,gy+1.0,0.0,origin,cw,ch),iso_pt(gx,gy+0.5,0.0,origin,cw,ch)];
    p.add(Shape::convex_polygon(left,Color32::from_rgb((col.r() as f32*0.6) as u8,(col.g() as f32*0.6) as u8,(col.b() as f32*0.6) as u8),Stroke::NONE));
    let right=vec![iso_pt(gx+0.5,gy+1.0,h,origin,cw,ch),iso_pt(gx+1.0,gy+0.5,h,origin,cw,ch),
                   iso_pt(gx+1.0,gy+0.5,0.0,origin,cw,ch),iso_pt(gx+0.5,gy+1.0,0.0,origin,cw,ch)];
    p.add(Shape::convex_polygon(right,Color32::from_rgb((col.r() as f32*0.45) as u8,(col.g() as f32*0.45) as u8,(col.b() as f32*0.45) as u8),Stroke::NONE));
}

fn waves_paint(painter: &Painter, rect: Rect, rows: &VecDeque<Vec<f32>>, pri: Color32) {
    painter.rect_filled(rect,Rounding::same(0.0),Color32::from_rgb(4,5,9));
    if rows.is_empty(){return;}
    let rh=rect.height()/WATERFALL_ROWS as f32; let cw=rect.width()/WATERFALL_COLS as f32;
    let[pr,pg,pb,_]=pri.to_array();
    for(r,row) in rows.iter().enumerate(){
        for(c,&v) in row.iter().enumerate(){
            if v<0.015{continue;}
            let t=v.clamp(0.0,1.0);
            let col=Color32::from_rgb(((pr as f32)*t).min(255.0) as u8,((pg as f32)*t*0.85).min(255.0) as u8,((pb as f32)*t*0.7).min(255.0) as u8);
            painter.rect_filled(Rect::from_min_size(Pos2::new(rect.min.x+c as f32*cw,rect.min.y+r as f32*rh),Vec2::new(cw+0.5,rh+0.5)),Rounding::ZERO,col);
        }
    }
    painter.rect_stroke(rect,Rounding::same(2.0),Stroke::new(1.0,Color32::from_rgb(18,25,40)));
}

fn draw_device_map(
    ui: &mut egui::Ui,
    devs: &[Peer],
    selected_ip: Option<&str>,
    router: (usize, usize),
    pri: Color32,
    sec: Color32,
    acc: Color32,
    h: f32,
) {
    let avail_w=ui.available_width();
    let cw=(avail_w/GRID_SIZE as f32).min(16.0).max(5.0); let ch=cw*0.5;
    let actual_h=(GRID_SIZE as f32*ch+ch*5.0).max(h);
    let(rect,_)=ui.allocate_exact_size(Vec2::new(avail_w,actual_h),egui::Sense::hover());
    let origin=Pos2::new(rect.center().x,rect.top()+ch*2.0);
    let painter=ui.painter_at(rect);
    painter.rect_filled(rect,Rounding::same(0.0),Color32::from_rgb(4,5,9));
    let (cx, cy) = router;
    let scale=(GRID_SIZE as f64/2.0-3.0)/20.0;
    for dist_m in [1.0f64,5.0,10.0,15.0,20.0] {
        let dist_cells=(dist_m*scale) as f32;
        let alpha=(0.35-dist_m as f32/80.0).max(0.08);
        let[pr,pg,pb,_]=pri.to_array();
        let rc=Color32::from_rgba_unmultiplied(
            (pr as f32*alpha) as u8,(pg as f32*alpha) as u8,(pb as f32*alpha) as u8,(255.0*alpha*1.5).min(255.0) as u8);
        let pts:Vec<Pos2>=(0..=40).map(|i|{
            let a=i as f32*std::f32::consts::TAU/40.0;
            iso_pt(cx as f32+a.cos()*dist_cells,cy as f32+a.sin()*dist_cells,0.0,origin,cw,ch)
        }).collect();
        for i in 0..pts.len()-1{ painter.line_segment([pts[i],pts[i+1]],Stroke::new(1.0,rc)); }
        let lp=iso_pt(cx as f32+dist_cells,cy as f32,0.0,origin,cw,ch);
        painter.text(lp+Vec2::new(4.0,0.0),egui::Align2::LEFT_CENTER,&format!("{:.0}m",dist_m),egui::FontId::monospace(8.0),rc);
    }
    for i in (0..GRID_SIZE).step_by(5) {
        let s1=iso_pt(i as f32,0.0,0.0,origin,cw,ch);let e1=iso_pt(i as f32,GRID_SIZE as f32,0.0,origin,cw,ch);
        painter.line_segment([s1,e1],Stroke::new(0.5,Color32::from_rgb(12,16,24)));
        let s2=iso_pt(0.0,i as f32,0.0,origin,cw,ch);let e2=iso_pt(GRID_SIZE as f32,i as f32,0.0,origin,cw,ch);
        painter.line_segment([s2,e2],Stroke::new(0.5,Color32::from_rgb(12,16,24)));
    }
    let rt=iso_pt(cx as f32+0.5,cy as f32+0.5,4.2,origin,cw,ch);
    for dev in devs {
        let dp=iso_pt(dev.gx as f32+0.5,dev.gy as f32+0.5,0.4,origin,cw,ch);
        let selected = selected_ip.map(|ip| ip == dev.ip).unwrap_or(false);
        let lc=if dev.is_wifi{acc}else{sec};
        let alpha=if selected{0.9}else if dev.up{0.45}else{0.15};
        painter.line_segment([rt,dp],Stroke::new(0.8,lc.linear_multiply(alpha)));
    }
    paint_block(&painter,cx as f32,cy as f32,4.0,origin,cw,ch,pri);
    painter.circle_filled(rt,cw*0.48,pri);
    painter.circle_stroke(rt,cw*0.85,Stroke::new(1.2,pri.linear_multiply(0.35)));
    painter.text(rt+Vec2::new(0.0,-cw*0.8),egui::Align2::CENTER_BOTTOM,"ROUTER",egui::FontId::monospace(8.0),pri);
    for dev in devs {
        let selected = selected_ip.map(|ip| ip == dev.ip).unwrap_or(false);
        let hb: f32 = if dev.is_wifi {
            (0.5+((dev.rssi+90.0)/70.0).clamp(0.0,1.0)*2.5) as f32
        } else {
            if dev.ping<1.0{2.5}else if dev.ping<5.0{1.5}else{0.7}
        };
        let base_col=if !dev.up{Color32::from_rgb(70,40,40)}else if dev.is_wifi{acc}else{sec};
        let col=if selected { Color32::from_rgb(255,220,120) } else { base_col };
        let node_h = if selected { hb + 0.5 } else { hb };
        paint_block(&painter,dev.gx as f32,dev.gy as f32,node_h,origin,cw,ch,col);
        let top=iso_pt(dev.gx as f32+0.5,dev.gy as f32+0.5,node_h+0.4,origin,cw,ch);
        let name=if !dev.host.is_empty()&&dev.host.len()<20{
            dev.host.split('.').next().unwrap_or(&dev.ip).to_string()
        } else {
            format!(".{}", dev.ip.split('.').last().unwrap_or(&dev.ip))
        };
        painter.circle_filled(top,cw*0.28,col);
        if selected { painter.circle_stroke(top,cw*0.38,Stroke::new(1.3,Color32::from_rgb(255,245,180))); }
        painter.text(top+Vec2::new(0.0,-cw*0.5),egui::Align2::CENTER_BOTTOM,&name,egui::FontId::monospace(8.0),col);
        if dev.is_wifi && dev.rssi>-200.0 {
            painter.text(top+Vec2::new(0.0,cw*0.1),egui::Align2::CENTER_TOP,
                &format!("{:.0}dBm",dev.rssi),egui::FontId::monospace(7.0),col.linear_multiply(0.65));
        } else if dev.up {
            painter.text(top+Vec2::new(0.0,cw*0.1),egui::Align2::CENTER_TOP,
                &format!("{:.1}ms",dev.ping),egui::FontId::monospace(7.0),col.linear_multiply(0.65));
        }
    }
    painter.rect_stroke(rect,Rounding::same(2.0),Stroke::new(1.0,Color32::from_rgb(18,25,40)));
}


fn status_col(s:&TestStatus,pri:Color32)->Color32{match s{TestStatus::Pass=>Color32::from_rgb(0,220,100),TestStatus::Warn=>Color32::from_rgb(255,180,0),TestStatus::Fail=>Color32::from_rgb(220,55,55),TestStatus::Running=>pri,TestStatus::Idle=>Color32::from_rgb(55,65,85)}}

fn status_lbl(s:&TestStatus)->&'static str{match s{TestStatus::Pass=>"PASS",TestStatus::Warn=>"WARN",TestStatus::Fail=>"FAIL",TestStatus::Running=>"....",TestStatus::Idle=>"IDLE"}}


impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(50));
        let pri=self.theme.primary(); let sec=self.theme.secondary(); let acc=self.theme.accent();
        let is_on=self.sound_active.load(Ordering::Relaxed);
        let(bps,rssi,pps,errs,db_hist)=self.get_series();
        let(now_bps,now_rssi,now_pps,now_errs,now_db,pk_bps,pk_rssi,wf)={
            let d=self.data.lock();
            (d.now_bps,d.now_rssi,d.now_pps,d.now_errs,d.now_db,
             d.peak_bps,d.peak_rssi,d.waves.clone())
        };
        let associated_wifi: Vec<Peer> = {
            let d = self.devices.lock();
            d.list.iter().filter(|dev| dev.is_wifi).cloned().collect()
        };
        if let Some(sel) = self.selected_assoc_ip.clone() {
            if !associated_wifi.iter().any(|d| d.ip == sel) {
                self.selected_assoc_ip = None;
            }
        }
        let gain=*self.gain_db.lock(); let wfm=*self.waveform.lock(); let sp=*self.speed.lock();

        egui::SidePanel::left("ctrl").resizable(false).exact_width(204.0)
            .frame(egui::Frame::none().fill(Color32::from_rgb(5,7,12)).stroke(Stroke::new(1.0,Color32::from_rgb(16,22,36))).inner_margin(egui::Margin::same(10.0)))
            .show(ctx,|ui|{
                ui.spacing_mut().item_spacing=Vec2::new(4.0,4.0);
                egui::Frame::none().fill(Color32::from_rgb(8,11,20)).rounding(Rounding::same(4.0)).stroke(Stroke::new(1.0,pri.linear_multiply(0.35))).inner_margin(egui::Margin::same(10.0)).show(ui,|ui|{
                    ui.label(RichText::new("Advanced Wifi Tools").size(16.0).color(pri).strong());
                    ui.label(RichText::new("Watch and test").size(10.0).color(sec));
                    ui.add_space(5.0);
                    ui.horizontal(|ui|{
                        let dot=if is_on{Color32::from_rgb(0,255,120)}else{Color32::from_rgb(45,55,72)};
                        ui.painter().circle_filled(ui.cursor().min+Vec2::new(5.0,7.0),4.0,dot);
                        ui.add_space(13.0);
                        ui.label(RichText::new(if is_on{"Listening..."}else{"Off"}).size(9.0).color(dot));
                    });
                    ui.add_space(3.0);
                    ui.label(RichText::new(format!("Up for       {}",fmt_up(self.uptime.elapsed()))).size(9.0).monospace().color(Color32::from_rgb(50,66,88)));
                    let cur_iface_label=self.selected_iface.lock().clone();
                    ui.label(RichText::new(format!("Using       {}",cur_iface_label)).size(9.0).monospace().color(Color32::from_rgb(50,66,88)));
                    ui.add_space(2.0);
                    egui::ComboBox::from_id_source("iface_combo").selected_text(RichText::new(&cur_iface_label).size(10.0).color(pri)).width(182.0).show_ui(ui,|ui|{
                        let ifaces=self.available_ifaces.clone();
                        for iface in &ifaces {
                            let sel=iface==&cur_iface_label;
                            if ui.selectable_label(sel,RichText::new(iface).size(10.0).monospace().color(if sel{pri}else{Color32::from_rgb(140,160,190)})).clicked(){
                                *self.selected_iface.lock()=iface.clone();
                            }
                        }
                    });
                    let dev=if self.device_name.len()>20{format!("{}..",&self.device_name[..18])}else{self.device_name.clone()};
                    let dcol=if self._audio.is_some(){Color32::from_rgb(50,66,88)}else{Color32::from_rgb(180,60,50)};
                    ui.label(RichText::new(format!("Out to      {}",dev)).size(9.0).monospace().color(dcol));
                });
                ui.add_space(7.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"Hello!");
                    if associated_wifi.is_empty() {
                        ui.label(RichText::new("-------------------").size(9.0).monospace().color(Color32::from_rgb(90,110,140)));
                    } else {
                        egui::ScrollArea::vertical().id_source("assoc_wifi_select").max_height(118.0).show(ui, |ui| {
                            for dev in &associated_wifi {
                                let selected = self.selected_assoc_ip.as_deref() == Some(dev.ip.as_str());
                                let mut label = dev.ip.clone();
                                if !dev.host.is_empty() {
                                    label = format!("{}  {}", dev.ip, dev.host.split('.').next().unwrap_or(""));
                                }
                                if ui.selectable_label(selected, RichText::new(label).size(9.5).monospace()).clicked() {
                                    self.selected_assoc_ip = Some(dev.ip.clone());
                                }
                            }
                        });
                        if let Some(ip)=&self.selected_assoc_ip {
                            ui.label(RichText::new(format!("Tracking: {}",ip)).size(9.0).monospace().color(acc));
                        }
                    }
                });
                ui.add_space(5.0);
                card(ui,if is_on{pri.linear_multiply(0.32)}else{Color32::from_rgb(18,24,38)},|ui|{
                    section(ui,"Convert Into Sound(LOUD)");
                    if big_btn(ui,if is_on{"Mute Sound"}else{"Turn on Audio"},is_on,pri,acc){
                        if is_on {
                            self.sound_active.store(false, Ordering::Relaxed);
                        } else {
                            if self._audio.is_none() {
                                if let Some((s, n)) = build_audio(self.data.clone(), self.sound_active.clone(), self.waveform.clone(), self.gain_db.clone()) {
                                    self._audio = Some(s);
                                    self.device_name = n;
                                } else {
                                    self.device_name = "No speaker found".to_string();
                                }
                            }
                            if self._audio.is_some() {
                                self.sound_active.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                });
                ui.add_space(5.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"Graph Sound Type");
                    ui.horizontal_wrapped(|ui|{for w in[Waveform::Sine,Waveform::Square,Waveform::Saw,Waveform::Triangle]{if pill(ui,w.label(),wfm==w,pri){*self.waveform.lock()=w;}}});
                });
                ui.add_space(5.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"Volume");
                    ui.horizontal(|ui|{
                        if pill(ui,"Lower",false,pri){let mut g=self.gain_db.lock();*g=(*g-3.0).clamp(-30.0,20.0);}
                        egui::Frame::none().fill(Color32::from_rgb(10,13,20)).stroke(Stroke::new(1.0,sec.linear_multiply(0.4))).rounding(Rounding::same(3.0)).inner_margin(egui::Margin::symmetric(6.0,4.0)).show(ui,|ui|{ui.label(RichText::new(format!("{:+.0} dB",gain)).size(12.0).monospace().color(sec).strong());});
                        if pill(ui,"Louder",false,acc){let mut g=self.gain_db.lock();*g=(*g+3.0).clamp(-30.0,20.0);}
                    });
                });
                ui.add_space(5.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"Graph Speed");
                    ui.horizontal_wrapped(|ui|{for(l,v) in[("Slower",0.5f32),("Normal",1.0),("Fast",2.0),("Very Fast",5.0)]{if pill(ui,l,(sp-v).abs()<0.01,pri){*self.speed.lock()=v;}}});
                });
                ui.add_space(5.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"View Options");
                    ui.horizontal(|ui|{
                        if pill(ui,"Freeze",self.frozen,acc){
                            self.frozen=!self.frozen;
                            if self.frozen{self.snap_bps=bps.clone();self.snap_rssi=rssi.clone();self.snap_pps=pps.clone();self.snap_errs=errs.clone();self.snap_db=db_hist.clone();}
                        }
                        if pill(ui,"Smooth",self.smoothing,pri){self.smoothing=!self.smoothing;}
                    });
                    ui.horizontal(|ui|{
                        if pill(ui,"Peaks",self.show_peaks,sec){self.show_peaks=!self.show_peaks;}
                        if pill(ui,"Log Plot",self.log_scale,pri){self.log_scale=!self.log_scale;}
                    });
                    if pill(ui,"Wipe History",false,Color32::from_rgb(200,55,55)){
                        let mut d=self.data.lock();
                        d.bps_h.clear();d.rssi_h.clear();d.pps_h.clear();d.errs_h.clear();d.db_h.clear();d.waves.clear();d.peak_bps=0.0;d.peak_rssi=-90.0;
                    }
                });
                ui.add_space(5.0);
                card(ui,Color32::from_rgb(18,24,38),|ui|{
                    section(ui,"Look & Feel");
                    ui.horizontal(|ui|{for t in[Theme::Cyan,Theme::Green,Theme::Amber]{if pill(ui,t.label(),self.theme==t,t.primary()){self.theme=t;}}});
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Color32::from_rgb(6,8,14)).inner_margin(egui::Margin::same(10.0)))
            .show(ctx,|ui|{
                ui.horizontal(|ui|{
                    for t in[Tab::Monitor,Tab::Devices,Tab::Tests]{
                        let on=self.tab==t;
                        let f=if on{pri.linear_multiply(0.18)}else{Color32::from_rgb(9,11,18)};
                        let s=if on{Stroke::new(1.5,pri)}else{Stroke::new(1.0,Color32::from_rgb(22,30,46))};
                        let tc=if on{pri}else{Color32::from_rgb(80,96,120)};
                        if ui.add(egui::Button::new(RichText::new(t.label()).size(11.0).monospace().color(tc).strong()).fill(f).stroke(s).rounding(Rounding::same(3.0)).min_size(Vec2::new(0.0,26.0))).clicked(){self.tab=t;}
                    }
                    if self.frozen{ui.with_layout(Layout::right_to_left(Align::Center),|ui|{ui.label(RichText::new("Snapshot mode").size(11.0).color(acc).strong());});}
                });
                ui.add_space(4.0); ui.separator(); ui.add_space(6.0);

                ui.horizontal(|ui|{
                    stat_tile(ui,"Network Flow",&fmt_bps(now_bps),&if self.show_peaks{format!("peak {}",fmt_bps(pk_bps))}else{String::new()},pri);
                    ui.add_space(3.0);
                    stat_tile(ui,"Health(NOT FOR LAN)",&format!("{:.1} dBm",now_rssi),&if self.show_peaks{format!("peak {:.1}",pk_rssi)}else{String::new()},sec);
                    ui.add_space(3.0);
                    stat_tile(ui,"Packets",&format!("{:.0}",now_pps),"/sec",acc);
                    ui.add_space(3.0);
                    stat_tile(ui,"Errors",&format!("{:.0}/s",now_errs),"",Color32::from_rgb(220,75,55));
                    ui.add_space(3.0);
                    stat_tile(ui,"Volume",&format!("{:.1}",now_db),"RMS",pri);
                    ui.add_space(3.0);
                });
                ui.add_space(6.0);

                match self.tab {

                    Tab::Monitor => {
                        let avail=ui.available_size(); let lw=avail.x*0.615; let rw=avail.x-lw-8.0; let ch=(avail.y-54.0)/3.5;
                        ui.horizontal(|ui|{
                            ui.vertical(|ui|{
                                ui.set_width(lw);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{line_chart(ui,"bps","Network Traffic Flow",&bps,pri,ch,0.0,None,self.log_scale);});
                                ui.add_space(4.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{line_chart(ui,"rssi","Signal Strength Over Time",&rssi,sec,ch,-90.0,Some(-20.0),false);});
                                ui.add_space(4.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    dual_line_chart(ui,"pps","Packets & Stability",&pps,acc,&errs,Color32::from_rgb(215,65,50),ch);
                                });
                            });
                            ui.add_space(8.0);
                            ui.vertical(|ui|{
                                ui.set_width(rw);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    ui.label(RichText::new("Volume History").size(10.0).color(Color32::from_rgb(85,106,138)));
                                    bar_chart(ui,"dbbars_out",&db_hist,pri,ch);
                                });
                                ui.add_space(4.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    ui.label(RichText::new("Current Numbers").size(10.0).color(Color32::from_rgb(85,106,138)));
                                    for(lbl,val,lo,hi,col) in [
                                        ("Loudness", now_db,  -80.0,0.0,   pri),
                                        ("Speed",    now_bps,  0.0,125e6,  acc),
                                        ("Signal",   now_rssi,-90.0,-20.0, Color32::from_rgb(160,200,255)),
                                        ("Activity", now_pps,  0.0,100000.0,Color32::from_rgb(200,180,100)),
                                    ] {
                                        ui.add_space(2.0);
                                        ui.label(RichText::new(lbl).size(9.0).monospace().color(Color32::from_rgb(55,70,92)));
                                        bar_meter(ui,val,lo,hi,col,13.0, lbl == "Signal" && !self.is_wifi_selected());
                                    }
                                });
                                ui.add_space(4.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    ui.label(RichText::new(" ").size(10.0).color(Color32::from_rgb(85,106,138)));
                                    let(rect,_)=ui.allocate_exact_size(Vec2::new(ui.available_width(),ch*1.2),egui::Sense::hover());
                                    waves_paint(&ui.painter_at(rect),rect,&wf,pri);
                                });
                            });
                        });
                    }

                    Tab::Devices => {
                        let avail=ui.available_size(); let lw=avail.x*0.45; let rw=avail.x-lw-8.0;
                        let (devs, scanning, last_scan, dev_log) = {
                            let d = self.devices.lock();
                            (d.list.clone(), d.active, d.last, d.log.clone())
                        };
                        let router = (GRID_SIZE/2, GRID_SIZE/2);
                        let map_on = self.map_enabled.load(Ordering::Relaxed);
                        ui.horizontal(|ui|{
                            ui.vertical(|ui|{
                                ui.set_width(lw);
                                card(ui,pri.linear_multiply(0.3),|ui|{
                                    section(ui,"Discovery Tools(MIGHT NOT BE ACCURATE)");
                                    ui.horizontal(|ui|{
                                        if big_btn(ui,if map_on{"Hide Map"}else{"Show Map"},map_on,pri,acc){
                                            self.map_enabled.store(!map_on, Ordering::Relaxed);
                                        }
                                    });
                                    ui.add_space(3.0);
                                    ui.horizontal(|ui|{
                                        if big_btn(ui,if scanning{"Fetching..."}else{"Scan Network Now"},scanning && map_on,pri,acc){
                                            if !scanning { self.dev_trigger.store(true,Ordering::Relaxed); }
                                        }
                                    });
                                    ui.add_space(3.0);
                                    ui.horizontal(|ui|{
                                        stat_tile(ui,"Total",&format!("{}",devs.len()),"",pri);
                                        ui.add_space(4.0);
                                        let up=devs.iter().filter(|d|d.up).count();
                                        stat_tile(ui,"Online",&format!("{}",up),"",Color32::from_rgb(0,200,100));
                                        ui.add_space(4.0);
                                        let wifi=devs.iter().filter(|d|d.is_wifi).count();
                                        stat_tile(ui,"Wireless",&format!("{}",wifi),"",acc);
                                    });
                                    if let Some(t)=last_scan{ui.add_space(3.0);ui.label(RichText::new(format!("Last seen {:.0}s ago",t.elapsed().as_secs_f32())).size(9.0).monospace().color(Color32::from_rgb(50,66,88)));}
                                });
                                ui.add_space(5.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    section(ui,"Network Peers");
                                    ui.horizontal(|ui|{
                                        for(lbl,w) in[("ST",20.0),("ADDRESS",110.0),("PING",52.0),("DIST",52.0),("TYPE",40.0),("NAME",0.0)]{
                                            ui.add_sized(Vec2::new(w,14.0),egui::Label::new(RichText::new(lbl).size(9.0).monospace().color(Color32::from_rgb(55,70,92))));
                                        }
                                    });
                                    ui.separator();
                                    let row_h=avail.y-200.0;
                                    egui::ScrollArea::vertical().id_source("devices_table_scroll").max_height(row_h.max(100.0)).show(ui,|ui|{
                                        for dev in &devs {
                                            ui.push_id(format!("dev_row_{}_{}", dev.ip, dev.mac), |ui| {
                                                let st_col=if dev.up{Color32::from_rgb(0,200,100)}else{Color32::from_rgb(120,50,50)};
                                                let tc=if dev.is_wifi{acc}else{sec};
                                                ui.horizontal(|ui|{
                                                    let(r,_)=ui.allocate_exact_size(Vec2::new(20.0,14.0),egui::Sense::hover());
                                                    ui.painter_at(r).circle_filled(r.center(),4.0,st_col);
                                                    ui.add_sized(Vec2::new(110.0,14.0),egui::Label::new(RichText::new(&dev.ip).size(10.0).monospace().color(tc)));
                                                    let ping_s=if dev.up{format!("{:.1}ms",dev.ping)}else{"--".to_string()};
                                                    let pc=if dev.ping<1.0{Color32::from_rgb(0,200,100)}else if dev.ping<10.0{Color32::from_rgb(255,180,0)}else{Color32::from_rgb(220,75,55)};
                                                    ui.add_sized(Vec2::new(52.0,14.0),egui::Label::new(RichText::new(ping_s).size(10.0).monospace().color(if dev.up{pc}else{Color32::from_rgb(55,65,80)})));
                                                    let dc=if dev.dist<5.0{Color32::from_rgb(0,200,100)}else if dev.dist<12.0{Color32::from_rgb(255,180,0)}else{Color32::from_rgb(220,75,55)};
                                                    ui.add_sized(Vec2::new(52.0,14.0),egui::Label::new(RichText::new(format!("{:.1}m",dev.dist)).size(10.0).monospace().color(dc)));
                                                    let type_s=if dev.is_wifi{"WiFi"}else{"Wire"};
                                                    ui.add_sized(Vec2::new(40.0,14.0),egui::Label::new(RichText::new(type_s).size(10.0).monospace().color(if dev.is_wifi{acc}else{Color32::from_rgb(80,100,130)})));
                                                    let hn=if dev.host.is_empty(){&dev.mac}else{&dev.host};
                                                    ui.label(RichText::new(hn).size(9.0).monospace().color(Color32::from_rgb(70,88,110)));
                                                });
                                            });
                                        }
                                        if devs.is_empty()&&!scanning {
                                            ui.add_space(10.0);
                                            ui.label(RichText::new("No peers found yet. Try a scan.").size(10.0).monospace().color(Color32::from_rgb(55,70,90)));
                                        }
                                    });
                                });
                                ui.add_space(5.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    section(ui,"Discovery Log");
                                    let lh=(ui.available_height()-20.0).max(60.0);
                                    egui::ScrollArea::vertical().id_source("devices_log_scroll").max_height(lh).stick_to_bottom(true).show(ui,|ui|{
                                        for line in &dev_log {
                                            ui.label(RichText::new(line).size(9.0).monospace().color(Color32::from_rgb(60,80,110)));
                                        }
                                    });
                                });
                            });
                            ui.add_space(8.0);
                            ui.vertical(|ui|{
                                ui.set_width(rw);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    if map_on {
                                        ui.label(RichText::new("Visual Network Map").size(10.0).color(Color32::from_rgb(85,106,138)));
                                        ui.add_space(2.0);
                                        ui.horizontal(|ui|{
                                            ui.label(RichText::new("Heigher means stronger signal").size(9.0).monospace().color(Color32::from_rgb(55,70,92)));
                                            ui.add_space(8.0);
                                            let wc=acc; let lc=sec;
                                            let(wr,_)=ui.allocate_exact_size(Vec2::new(10.0,10.0),egui::Sense::hover()); ui.painter_at(wr).rect_filled(wr,Rounding::same(1.0),wc);
                                            ui.label(RichText::new("WiFi").size(9.0).monospace().color(wc));
                                            ui.add_space(4.0);
                                            let(lr,_)=ui.allocate_exact_size(Vec2::new(10.0,10.0),egui::Sense::hover()); ui.painter_at(lr).rect_filled(lr,Rounding::same(1.0),lc);
                                            ui.label(RichText::new("LAN").size(9.0).monospace().color(lc));
                                        });
                                        draw_device_map(ui,&devs,self.selected_assoc_ip.as_deref(),router,pri,sec,acc,avail.y-90.0);
                                        if let Some(ip) = &self.selected_assoc_ip {
                                            ui.label(RichText::new(format!("Watching: {}", ip)).size(9.0).monospace().color(Color32::from_rgb(120,145,180)));
                                        }
                                    } else {
                                        ui.label(RichText::new("Map is paused").size(14.0).color(Color32::from_rgb(120,140,170)).strong());
                                        ui.label(RichText::new("Press Show Map the switch to start scanning.").size(10.0).monospace().color(Color32::from_rgb(85,106,138)));
                                    }
                                });
                            });
                        });
                    }

                    Tab::Tests => {
                        let avail=ui.available_size(); let lw=avail.x*0.62; let rw=avail.x-lw-8.0;
                        ui.horizontal(|ui|{
                            ui.vertical(|ui|{
                                ui.set_width(lw);
                                card(ui,pri.linear_multiply(0.3),|ui|{
                                    let running=self.tests.lock().busy;
                                    if big_btn(ui,if running{"Testing your wires..."}else{"Check Everything"},running,pri,acc) {
                                        if !running {
                                            self.tests.lock().busy=true;
                                            let tr=self.tests.clone(); let bs=now_bps; let es=now_errs;
                                            let all:Vec<Check>=self.tests.lock().tasks.clone();
                                            thread::spawn(move||{
                                                for entry in all {
                                                    {let mut t=tr.lock();if let Some(e)=t.tasks.iter_mut().find(|e|e.name==entry.name){e.state=TestStatus::Running;}t.log(&format!(">> {}...",entry.name));}
                                                    let(st,val,res)=run_test_entry(entry.clone(),(bs,es));
                                                    let mut t=tr.lock();
                                                    if let Some(e)=t.tasks.iter_mut().find(|e2|e2.name==entry.name){e.state=st.clone();e.val=val;e.out=res.clone();push_dq(&mut e.history,val);}
                                                    t.log(&format!("   {} -> {} [{}]",entry.name,status_lbl(&st),res));
                                                }
                                                tr.lock().busy=false;
                                            });
                                        }
                                    }
                                });
                                ui.add_space(5.0);
                                let entries:Vec<Check>=self.tests.lock().tasks.clone();
                                for entry in &entries {
                                    let sc=status_col(&entry.state,pri);
                                    card(ui,sc.linear_multiply(0.3),|ui|{
                                        ui.horizontal(|ui|{
                                            egui::Frame::none().fill(sc.linear_multiply(0.2)).stroke(Stroke::new(1.0,sc)).rounding(Rounding::same(2.0)).inner_margin(egui::Margin::symmetric(5.0,3.0)).show(ui,|ui|{ui.label(RichText::new(status_lbl(&entry.state)).size(9.0).monospace().color(sc).strong());});
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(&entry.name).size(11.0).monospace().color(Color32::from_rgb(180,200,230)).strong());
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(&entry.target).size(9.0).monospace().color(Color32::from_rgb(60,78,100)));
                                            ui.with_layout(Layout::right_to_left(Align::Center),|ui|{
                                                let en=entry.clone(); let tr=self.tests.clone(); let bs=now_bps; let es=now_errs;
                                                if entry.state!=TestStatus::Running {
                                                    ui.push_id(format!("run_btn_{}", entry.name), |ui| {
                                                        if pill(ui,"RUN",false,pri){
                                                            thread::spawn(move||{
                                                                {let mut t=tr.lock();if let Some(e)=t.tasks.iter_mut().find(|e|e.name==en.name){e.state=TestStatus::Running;}t.log(&format!(">> {}...",en.name));}
                                                                let(st,val,res)=run_test_entry(en.clone(),(bs,es));
                                                                let mut t=tr.lock();if let Some(e)=t.tasks.iter_mut().find(|e2|e2.name==en.name){e.state=st.clone();e.val=val;e.out=res.clone();push_dq(&mut e.history,val);}
                                                                t.log(&format!("   {} [{}]",status_lbl(&st),res));
                                                            });
                                                        }
                                                    });
                                                }
                                                ui.add_space(4.0);
                                                if entry.state!=TestStatus::Idle{ui.label(RichText::new(format!("{} {}",&entry.out,&entry.unit)).size(11.0).monospace().color(sc).strong());}
                                            });
                                        });
                                        if !entry.history.is_empty(){
                                            let pts:PlotPoints=entry.history.iter().enumerate().map(|(i,&v)|[i as f64,v]).collect();
                                            Plot::new(format!("h_{}",&entry.name)).height(26.0).show_axes([false,false]).show_grid(false).allow_zoom(false).allow_drag(false).allow_scroll(false)
                                                .show(ui,|pu|{pu.line(Line::new(pts).color(sc).width(1.5));});
                                        }
                                    });
                                    ui.add_space(3.0);
                                }
                            });
                            ui.add_space(8.0);
                            ui.vertical(|ui|{
                                ui.set_width(rw);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    section(ui,"How Healthy is your Network?");
                                    let entries=self.tests.lock().tasks.clone();
                                    let pass=entries.iter().filter(|e|e.state==TestStatus::Pass).count();
                                    let warn=entries.iter().filter(|e|e.state==TestStatus::Warn).count();
                                    let fail=entries.iter().filter(|e|e.state==TestStatus::Fail).count();
                                    let total=pass+warn+fail;
                                    if total>0 {
                                        let score=(pass as f64/total as f64)*100.0;
                                        let sc=if score>=80.0{Color32::from_rgb(0,220,100)}else if score>=50.0{Color32::from_rgb(255,180,0)}else{Color32::from_rgb(220,55,55)};
                                        ui.label(RichText::new(format!("{:.0}/100",score)).size(28.0).monospace().color(sc).strong());
                                        ui.horizontal(|ui|{
                                            ui.label(RichText::new(format!("GOOD {}",pass)).size(11.0).monospace().color(Color32::from_rgb(0,200,100)));
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(format!("FAIR {}",warn)).size(11.0).monospace().color(Color32::from_rgb(255,180,0)));
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(format!("POOR {}",fail)).size(11.0).monospace().color(Color32::from_rgb(220,55,55)));
                                        });
                                        bar_meter(ui,score,0.0,100.0,sc,12.0, false);
                                    } else { ui.label(RichText::new("Run a check to see your score.").size(10.0).monospace().color(Color32::from_rgb(55,70,90))); }
                                });
                                ui.add_space(5.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    section(ui,"Stat");
                                    let gw=get_gateway().unwrap_or_else(||"unknown".to_string());
                                    for(l,v,c) in[
                                        ("GATEWAY", gw.clone(), Color32::from_rgb(120,150,190)),
                                        ("INTERFACE", self.selected_iface.lock().clone(), Color32::from_rgb(120,150,190)),
                                        ("NETWORK FLOW RATE", format!("{:.2} MB/s",now_bps/1e6), pri),
                                        ("ERROR", format!("{:.1}/s",now_errs), if now_errs>10.0{Color32::from_rgb(220,75,55)}else{Color32::from_rgb(0,200,100)}),
                                        ("VOLUME", format!("{:.1} (RMS)",now_db), sec),
                                    ]{ ui.label(RichText::new(format!("{:<12}{}",l,v)).size(10.0).monospace().color(c)); }
                                });
                                ui.add_space(5.0);
                                card(ui,Color32::from_rgb(14,20,34),|ui|{
                                    section(ui,"Past Events");
                                    let lh=(ui.available_height()-16.0).max(80.0);
                                    let log=self.tests.lock().log.clone();
                                    egui::ScrollArea::vertical().id_source("tests_log_scroll").max_height(lh).stick_to_bottom(true).show(ui,|ui|{
                                        for line in &log {
                                            let c=if line.starts_with("   PASS"){Color32::from_rgb(0,200,100)}else if line.starts_with("   WARN"){Color32::from_rgb(255,180,0)}else if line.starts_with("   FAIL"){Color32::from_rgb(220,55,55)}else if line.starts_with(">>"){pri}else{Color32::from_rgb(60,80,110)};
                                            ui.label(RichText::new(line).size(9.0).monospace().color(c));
                                        }
                                    });
                                });
                            });
                        });
                    }
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let data = Arc::new(Mutex::new(LiveStats::default()));
    let d2   = data.clone();
    eframe::run_native("AWSTT",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("AWSTT")
                .with_inner_size([1440.0, 880.0])
                .with_min_inner_size([1000.0, 650.0]),
            ..Default::default()
        },
        Box::new(move|cc|Ok(Box::new(App::new(cc, d2)))),
    )
}
