//! Best-effort automatic port forwarding + public-address discovery, in pure
//! std Rust (no external crates, no external services).
//!
//! Goal: right after configuration, make the server reachable from other
//! machines and surface a URL the operator can share — even with no DNS set up.
//!
//! Two router protocols are attempted, both implemented here from scratch:
//!   1. UPnP-IGD (self-discovering via SSDP multicast) — primary.
//!   2. NAT-PMP (RFC 6886) — fallback, needs the default gateway address.
//!
//! Everything is best-effort: failures are logged and never fatal. When the
//! router reports a *private* or CGNAT WAN address (i.e. we're behind
//! carrier-grade NAT / double NAT), we can detect that and tell the operator
//! honestly that inbound internet access is not possible without a relay,
//! rather than printing a URL that will not work.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use crate::config::Config;
use crate::util;

/// Outcome of a discovery+mapping attempt.
#[derive(Debug, Default, Clone)]
pub struct MapResult {
    /// Router's WAN/external IP, if discovered.
    pub external_ip: Option<String>,
    /// Which mechanism succeeded ("upnp" / "natpmp"), if any.
    pub method: Option<&'static str>,
    /// Ports successfully mapped inbound.
    pub mapped_ports: Vec<u16>,
    /// Ports that failed to map.
    pub failed_ports: Vec<u16>,
}

impl MapResult {
    /// True when we learned an external IP that is actually reachable from the
    /// public internet (not private, not loopback, not CGNAT).
    pub fn externally_reachable(&self) -> bool {
        self.external_ip
            .as_deref()
            .map(is_public_ipv4)
            .unwrap_or(false)
    }
}

/// True for an IPv4 address that is routable from the public internet: not
/// private (RFC 1918), loopback, link-local, unspecified, or CGNAT (RFC 6598,
/// 100.64.0.0/10 — the tell-tale of carrier-grade NAT).
pub fn is_public_ipv4(ip: &str) -> bool {
    match ip.parse::<Ipv4Addr>() {
        Ok(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || cgnat)
        }
        Err(_) => false,
    }
}

/// Build a shareable webmail URL for a public IP using sslip.io wildcard DNS
/// (`<ip>.sslip.io` resolves to `<ip>` with zero DNS configuration). The port
/// is omitted when it is the scheme default.
pub fn sslip_url(ip: &str, port: u16, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    let default_port = if https { 443 } else { 80 };
    if port == default_port {
        format!("{}://{}.sslip.io", scheme, ip)
    } else {
        format!("{}://{}.sslip.io:{}", scheme, ip, port)
    }
}

/// Build the bare-IP URL (works by typing the address directly).
pub fn ip_url(ip: &str, port: u16, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    let default_port = if https { 443 } else { 80 };
    if port == default_port {
        format!("{}://{}", scheme, ip)
    } else {
        format!("{}://{}:{}", scheme, ip, port)
    }
}

/// Discover the router and map `ports` (TCP) inbound to `internal_ip`.
/// Tries UPnP first (self-discovering), then NAT-PMP. Best-effort.
pub fn discover_and_map(internal_ip: &str, ports: &[u16], lease_secs: u32) -> MapResult {
    // UPnP-IGD via SSDP — no gateway address required.
    if let Some(igd) = upnp_discover() {
        let mut res = MapResult {
            method: Some("upnp"),
            external_ip: upnp_get_external_ip(&igd),
            ..Default::default()
        };
        for &p in ports {
            if upnp_add_mapping(&igd, internal_ip, p, lease_secs) {
                res.mapped_ports.push(p);
            } else {
                res.failed_ports.push(p);
            }
        }
        if res.external_ip.is_some() || !res.mapped_ports.is_empty() {
            return res;
        }
    }

    // NAT-PMP fallback — needs the default gateway.
    if let Some(gw) = default_gateway_v4() {
        let mut res = MapResult {
            method: Some("natpmp"),
            external_ip: natpmp_external_ip(gw).map(|ip| ip.to_string()),
            ..Default::default()
        };
        for &p in ports {
            if natpmp_map_port(gw, p, lease_secs) {
                res.mapped_ports.push(p);
            } else {
                res.failed_ports.push(p);
            }
        }
        return res;
    }

    MapResult::default()
}

// ---------------------------------------------------------------------------
// Public-access state + startup orchestration
// ---------------------------------------------------------------------------

/// What the operator (and installer / web UI) should be told about how to
/// reach this server from other machines.
#[derive(Debug, Clone, Default)]
pub struct PublicAccess {
    /// True when a URL that works from the public internet is available.
    pub reachable: bool,
    /// Router WAN IP, when discovered.
    pub external_ip: Option<String>,
    /// Shareable hostname URL via sslip.io (works without DNS).
    pub url: Option<String>,
    /// Bare-IP URL (alternative to the hostname form).
    pub ip_url: Option<String>,
    /// LAN URL (same-network fallback), always set when we know our LAN IP.
    pub lan_url: Option<String>,
    /// "upnp" / "natpmp" / "manual" (public_url override) / None.
    pub method: Option<&'static str>,
    /// Human-readable status / next-step guidance.
    pub note: String,
}

fn state() -> &'static RwLock<Option<PublicAccess>> {
    static S: OnceLock<RwLock<Option<PublicAccess>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(None))
}

/// Latest known public-access info (None until discovery completes).
pub fn current() -> Option<PublicAccess> {
    state().read().ok().and_then(|g| g.clone())
}

fn set_current(pa: PublicAccess) {
    if let Ok(mut g) = state().write() {
        *g = Some(pa);
    }
}

/// Extract the port from a `host:port` listen address.
pub fn port_of(listen: &str) -> Option<u16> {
    listen.rsplit(':').next()?.parse::<u16>().ok()
}

/// The webmail URL details we surface: (port, https).
fn web_endpoint(cfg: &Config) -> Option<(u16, bool)> {
    if !cfg.web_tls_listen.is_empty() {
        if let Some(p) = port_of(&cfg.web_tls_listen) {
            return Some((p, true));
        }
    }
    if !cfg.web_listen.is_empty() {
        if let Some(p) = port_of(&cfg.web_listen) {
            return Some((p, false));
        }
    }
    None
}

/// Collect the TCP ports we want reachable from outside (web + mail).
fn ports_to_map(cfg: &Config) -> Vec<u16> {
    let mut v = Vec::new();
    for l in [
        cfg.web_listen.as_str(),
        cfg.web_tls_listen.as_str(),
        cfg.smtp_listen.as_str(),
        cfg.submission_listen.as_str(),
        cfg.imap_listen.as_str(),
        cfg.smtps_listen.as_str(),
        cfg.imaps_listen.as_str(),
    ] {
        if l.is_empty() {
            continue;
        }
        if let Some(p) = port_of(l) {
            if p != 0 && !v.contains(&p) {
                v.push(p);
            }
        }
    }
    v
}

const PUBLIC_URL_FILE: &str = "public_url.txt";

fn write_state_file(cfg: &Config, pa: &PublicAccess) {
    let path = std::path::Path::new(&cfg.data_dir).join(PUBLIC_URL_FILE);
    let best = pa
        .url
        .clone()
        .or_else(|| pa.ip_url.clone())
        .or_else(|| pa.lan_url.clone())
        .unwrap_or_default();
    let body = format!(
        "url={}\nreachable={}\nmethod={}\nnote={}\n",
        best,
        pa.reachable,
        pa.method.unwrap_or("none"),
        pa.note
    );
    let _ = std::fs::write(path, body);
}

/// Kick off best-effort port forwarding + public-URL discovery in the
/// background (never blocks startup, never fatal). Renews UPnP/NAT-PMP leases
/// periodically so the mapping survives.
pub fn start(cfg: Arc<Config>) {
    std::thread::Builder::new()
        .name("portmap".into())
        .spawn(move || {
            // Operator override wins and needs no router work.
            let override_url = cfg.public_url_get();
            let lan = local_egress_ip();
            let (web_port, https) = web_endpoint(&cfg).unwrap_or((8080, false));
            let lan_url = lan.as_ref().map(|ip| ip_url(ip, web_port, https));

            if !override_url.is_empty() {
                let pa = PublicAccess {
                    reachable: true,
                    external_ip: None,
                    url: Some(override_url.clone()),
                    ip_url: None,
                    lan_url,
                    method: Some("manual"),
                    note: "Using operator-configured public_url.".into(),
                };
                util::log!("public URL (configured): {}", override_url);
                write_state_file(&cfg, &pa);
                set_current(pa);
                return;
            }

            if !cfg.auto_port_forward {
                let pa = manual_only(lan_url.clone());
                write_state_file(&cfg, &pa);
                set_current(pa);
                return;
            }

            let lease: u32 = 3600;
            let ports = ports_to_map(&cfg);
            loop {
                let res = discover_and_map(lan.as_deref().unwrap_or("0.0.0.0"), &ports, lease);
                let pa = build_access(&res, web_port, https, lan_url.clone());
                if let Some(m) = res.method {
                    util::log!(
                        "port-forward via {}: mapped {:?}, failed {:?}, wan_ip={:?}",
                        m,
                        res.mapped_ports,
                        res.failed_ports,
                        res.external_ip
                    );
                }
                if pa.reachable {
                    util::log!("public URL: {}", pa.url.clone().unwrap_or_default());
                } else {
                    util::log!("no public URL yet: {}", pa.note);
                }
                write_state_file(&cfg, &pa);
                set_current(pa);
                // Renew a little before the lease expires.
                std::thread::sleep(Duration::from_secs((lease as u64).saturating_sub(300).max(300)));
            }
        })
        .ok();
}

fn manual_only(lan_url: Option<String>) -> PublicAccess {
    PublicAccess {
        reachable: false,
        external_ip: None,
        url: None,
        ip_url: None,
        lan_url,
        method: None,
        note: "Automatic port-forwarding is disabled (auto_port_forward=false). \
               Configure your router/firewall manually, or set public_url."
            .into(),
    }
}

/// Turn a raw MapResult into operator-facing access info + guidance.
pub fn build_access(
    res: &MapResult,
    web_port: u16,
    https: bool,
    lan_url: Option<String>,
) -> PublicAccess {
    match &res.external_ip {
        Some(ip) if is_public_ipv4(ip) => PublicAccess {
            reachable: true,
            external_ip: Some(ip.clone()),
            url: Some(sslip_url(ip, web_port, https)),
            ip_url: Some(ip_url(ip, web_port, https)),
            lan_url,
            method: res.method,
            note: format!(
                "Reachable from the internet. Share this URL. \
                 (Mapped ports: {:?}.)",
                res.mapped_ports
            ),
        },
        Some(ip) => PublicAccess {
            // Router reports a private/CGNAT WAN IP → carrier-grade NAT.
            reachable: false,
            external_ip: Some(ip.clone()),
            url: None,
            ip_url: None,
            lan_url,
            method: res.method,
            note: format!(
                "Your router's WAN address ({}) is itself private (carrier-grade NAT). \
                 Inbound internet access is not possible without a relay/tunnel or a \
                 public IP from your ISP. The LAN URL works on your local network.",
                ip
            ),
        },
        None => PublicAccess {
            reachable: false,
            external_ip: None,
            url: None,
            ip_url: None,
            lan_url,
            method: res.method,
            note: "Could not auto-configure the router (UPnP/NAT-PMP unavailable). \
                   Forward the ports on your router manually, or set public_url. \
                   The LAN URL works on your local network."
                .into(),
        },
    }
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

const NATPMP_PORT: u16 = 5351;

/// Build the NAT-PMP "get external address" request (2 bytes: ver=0, op=0).
pub fn natpmp_ext_addr_request() -> [u8; 2] {
    [0, 0]
}

/// Parse a NAT-PMP external-address response.
/// Layout: ver(1)=0, op(1)=128, result(2), epoch(4), addr(4).
pub fn natpmp_parse_ext_addr(resp: &[u8]) -> Option<Ipv4Addr> {
    if resp.len() < 12 || resp[0] != 0 || resp[1] != 128 {
        return None;
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        return None;
    }
    Some(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]))
}

/// Build a NAT-PMP map request for a TCP port.
/// Layout: ver(1)=0, op(1)=2(TCP), reserved(2)=0, internal(2), external(2), lifetime(4).
pub fn natpmp_map_request(internal_port: u16, external_port: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0;
    b[1] = 2; // TCP
    // reserved [2..4] = 0
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&external_port.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// Parse a NAT-PMP map response -> (internal_port, external_port, lifetime).
/// Layout: ver(1)=0, op(1)=130(TCP map reply), result(2), epoch(4), internal(2), external(2), lifetime(4).
pub fn natpmp_parse_map_response(resp: &[u8]) -> Option<(u16, u16, u32)> {
    if resp.len() < 16 || resp[0] != 0 || resp[1] != 130 {
        return None;
    }
    if u16::from_be_bytes([resp[2], resp[3]]) != 0 {
        return None;
    }
    let internal = u16::from_be_bytes([resp[8], resp[9]]);
    let external = u16::from_be_bytes([resp[10], resp[11]]);
    let lifetime = u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]);
    Some((internal, external, lifetime))
}

fn natpmp_socket(gw: Ipv4Addr) -> Option<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(700))).ok()?;
    sock.set_write_timeout(Some(Duration::from_millis(700))).ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(gw), NATPMP_PORT)).ok()?;
    Some(sock)
}

fn natpmp_external_ip(gw: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = natpmp_socket(gw)?;
    sock.send(&natpmp_ext_addr_request()).ok()?;
    let mut buf = [0u8; 32];
    let n = sock.recv(&mut buf).ok()?;
    natpmp_parse_ext_addr(&buf[..n])
}

fn natpmp_map_port(gw: Ipv4Addr, port: u16, lifetime: u32) -> bool {
    let sock = match natpmp_socket(gw) {
        Some(s) => s,
        None => return false,
    };
    if sock.send(&natpmp_map_request(port, port, lifetime)).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    match sock.recv(&mut buf) {
        Ok(n) => natpmp_parse_map_response(&buf[..n]).is_some(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Default gateway discovery
// ---------------------------------------------------------------------------

/// Best-effort default IPv4 gateway.
pub fn default_gateway_v4() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(txt) = std::fs::read_to_string("/proc/net/route") {
            if let Some(gw) = parse_linux_default_gateway(&txt) {
                return Some(gw);
            }
        }
    }
    // Portable fallback: assume the gateway is the .1 host of our egress /24.
    // A wrong guess simply times out harmlessly.
    gateway_guess_from_egress()
}

/// Parse `/proc/net/route`, returning the gateway of the default route
/// (destination 00000000). Gateway field is little-endian hex.
pub fn parse_linux_default_gateway(contents: &str) -> Option<Ipv4Addr> {
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        if f[1] != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(f[2], 16).ok()?;
        // Little-endian in the file.
        let o = raw.to_le_bytes();
        return Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
    }
    None
}

fn egress_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

fn gateway_guess_from_egress() -> Option<Ipv4Addr> {
    let v4 = egress_ipv4()?;
    let o = v4.octets();
    Some(Ipv4Addr::new(o[0], o[1], o[2], 1))
}

/// Local egress IPv4 as a string (the LAN address to map to / show for LAN URL).
pub fn local_egress_ip() -> Option<String> {
    egress_ipv4().map(|v| v.to_string())
}

// ---------------------------------------------------------------------------
// UPnP-IGD (SSDP discovery + SOAP control)
// ---------------------------------------------------------------------------

/// A discovered IGD control endpoint.
#[derive(Debug, Clone)]
pub struct Igd {
    /// Full control URL, e.g. http://192.168.1.1:5000/ctl/IPConn
    pub control_url: String,
    /// Service type, e.g. urn:schemas-upnp-org:service:WANIPConnection:1
    pub service_type: String,
}

/// SSDP M-SEARCH datagram for IGD discovery.
pub fn ssdp_msearch_request() -> String {
    "M-SEARCH * HTTP/1.1\r\n\
     HOST: 239.255.255.250:1900\r\n\
     MAN: \"ssdp:discovery\"\r\n\
     MX: 2\r\n\
     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        .to_string()
}

/// Extract the LOCATION header (device description URL) from an SSDP reply.
pub fn parse_ssdp_location(resp: &str) -> Option<String> {
    for line in resp.lines() {
        if let Some(rest) = line.splitn(2, ':').next().map(str::trim) {
            if rest.eq_ignore_ascii_case("location") {
                if let Some(v) = line.splitn(2, ':').nth(1) {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// From a device description XML, find a WAN{IP,PPP}Connection service and
/// return (controlURL, serviceType). controlURL may be relative.
pub fn parse_control_url(xml: &str) -> Option<(String, String)> {
    // Find a <service> block whose serviceType is WAN(IP|PPP)Connection.
    let mut search = 0usize;
    while let Some(rel) = xml[search..].find("<service>") {
        let start = search + rel;
        let end = xml[start..]
            .find("</service>")
            .map(|e| start + e)
            .unwrap_or(xml.len());
        let block = &xml[start..end];
        let stype = tag_text(block, "serviceType");
        if let Some(ref st) = stype {
            if st.contains("WANIPConnection") || st.contains("WANPPPConnection") {
                if let Some(ctrl) = tag_text(block, "controlURL") {
                    return Some((ctrl, st.clone()));
                }
            }
        }
        search = end + 1;
        if search >= xml.len() {
            break;
        }
    }
    None
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(xml[s..e].trim().to_string())
}

/// SOAP body for GetExternalIPAddress.
pub fn soap_get_external_ip_body(service_type: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:GetExternalIPAddress xmlns:u=\"{}\"></u:GetExternalIPAddress></s:Body></s:Envelope>",
        service_type
    )
}

/// SOAP body for AddPortMapping (TCP).
pub fn soap_add_port_mapping_body(
    service_type: &str,
    external_port: u16,
    internal_port: u16,
    internal_client: &str,
    lease_secs: u32,
) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:AddPortMapping xmlns:u=\"{st}\">\
<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{ext}</NewExternalPort>\
<NewProtocol>TCP</NewProtocol>\
<NewInternalPort>{int}</NewInternalPort>\
<NewInternalClient>{ip}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>DesertEmail</NewPortMappingDescription>\
<NewLeaseDuration>{lease}</NewLeaseDuration>\
</u:AddPortMapping></s:Body></s:Envelope>",
        st = service_type,
        ext = external_port,
        int = internal_port,
        ip = internal_client,
        lease = lease_secs
    )
}

/// Parse <NewExternalIPAddress> out of a SOAP response.
pub fn parse_soap_external_ip(xml: &str) -> Option<String> {
    tag_text(xml, "NewExternalIPAddress").filter(|s| !s.is_empty())
}

fn upnp_discover() -> Option<Igd> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1200))).ok()?;
    let dst: SocketAddr = "239.255.255.250:1900".parse().ok()?;
    let msg = ssdp_msearch_request();
    let _ = sock.send_to(msg.as_bytes(), dst);
    // Read a few replies; take the first that yields a usable control URL.
    let mut buf = [0u8; 4096];
    for _ in 0..4 {
        let (n, _from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => break,
        };
        let resp = String::from_utf8_lossy(&buf[..n]);
        if let Some(loc) = parse_ssdp_location(&resp) {
            if let Some(igd) = upnp_fetch_igd(&loc) {
                return Some(igd);
            }
        }
    }
    None
}

fn upnp_fetch_igd(location: &str) -> Option<Igd> {
    let (host, port, path) = split_http_url(location)?;
    let xml = http_get(&host, port, &path)?;
    let (ctrl, stype) = parse_control_url(&xml)?;
    // Resolve relative controlURL against the description base.
    let control_url = if ctrl.starts_with("http://") || ctrl.starts_with("https://") {
        ctrl
    } else if let Some(stripped) = ctrl.strip_prefix('/') {
        format!("http://{}:{}/{}", host, port, stripped)
    } else {
        format!("http://{}:{}/{}", host, port, ctrl)
    };
    Some(Igd {
        control_url,
        service_type: stype,
    })
}

fn upnp_get_external_ip(igd: &Igd) -> Option<String> {
    let body = soap_get_external_ip_body(&igd.service_type);
    let action = format!("\"{}#GetExternalIPAddress\"", igd.service_type);
    let resp = soap_call(&igd.control_url, &action, &body)?;
    parse_soap_external_ip(&resp)
}

fn upnp_add_mapping(igd: &Igd, internal_ip: &str, port: u16, lease: u32) -> bool {
    let body = soap_add_port_mapping_body(&igd.service_type, port, port, internal_ip, lease);
    let action = format!("\"{}#AddPortMapping\"", igd.service_type);
    match soap_call(&igd.control_url, &action, &body) {
        // A 200 response with no SOAP <errorCode> means success.
        Some(resp) => !resp.contains("<errorCode>") && !resp.contains("faultstring"),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Minimal HTTP client (std TCP) for the local router only
// ---------------------------------------------------------------------------

/// Split `http://host:port/path` into (host, port, path). https not supported
/// (routers speak plain HTTP on the LAN); returns None otherwise.
pub fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), 80),
    };
    Some((host, port, path.to_string()))
}

fn connect(host: &str, port: u16) -> Option<TcpStream> {
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().ok().or_else(|| {
            // Resolve hostname (rare for routers, but be safe).
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs().ok()?.next()
        })?,
        Duration::from_millis(1200),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(1500))).ok()?;
    Some(stream)
}

fn http_get(host: &str, port: u16, path: &str) -> Option<String> {
    let mut stream = connect(host, port)?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nAccept: text/xml\r\n\r\n",
        path, host, port
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = stream.take(256 * 1024).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    Some(http_body(&text).to_string())
}

fn soap_call(control_url: &str, action: &str, body: &str) -> Option<String> {
    let (host, port, path) = split_http_url(control_url)?;
    let mut stream = connect(&host, port)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: {action}\r\n\
         Connection: close\r\n\
         Content-Length: {len}\r\n\r\n{body}",
        path = path,
        host = host,
        port = port,
        action = action,
        len = body.len(),
        body = body
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = stream.take(256 * 1024).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    Some(http_body(&text).to_string())
}

/// Return the body portion of an HTTP response (after the header block).
fn http_body(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[i + 4..],
        None => resp,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_classification() {
        assert!(is_public_ipv4("203.0.113.10") == false); // TEST-NET-3 (documentation)
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(is_public_ipv4("1.2.3.4"));
        assert!(!is_public_ipv4("192.168.1.10"));
        assert!(!is_public_ipv4("10.0.0.5"));
        assert!(!is_public_ipv4("172.16.4.1"));
        assert!(!is_public_ipv4("127.0.0.1"));
        assert!(!is_public_ipv4("100.64.0.1")); // CGNAT
        assert!(!is_public_ipv4("100.127.255.1")); // CGNAT upper
        assert!(is_public_ipv4("100.63.0.1")); // just below CGNAT
        assert!(is_public_ipv4("100.128.0.1")); // just above CGNAT
        assert!(!is_public_ipv4("not-an-ip"));
    }

    #[test]
    fn urls_omit_default_ports() {
        assert_eq!(sslip_url("1.2.3.4", 8080, false), "http://1.2.3.4.sslip.io:8080");
        assert_eq!(sslip_url("1.2.3.4", 80, false), "http://1.2.3.4.sslip.io");
        assert_eq!(sslip_url("1.2.3.4", 443, true), "https://1.2.3.4.sslip.io");
        assert_eq!(ip_url("1.2.3.4", 8080, false), "http://1.2.3.4:8080");
        assert_eq!(ip_url("1.2.3.4", 80, false), "http://1.2.3.4");
    }

    #[test]
    fn natpmp_request_and_parse_roundtrip() {
        let req = natpmp_map_request(2525, 25, 3600);
        assert_eq!(req[1], 2); // TCP
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 2525);
        assert_eq!(u16::from_be_bytes([req[6], req[7]]), 25);
        assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 3600);

        // Synthesise a valid map response.
        let mut resp = vec![0u8, 130, 0, 0, 0, 0, 0, 0];
        resp.extend_from_slice(&2525u16.to_be_bytes());
        resp.extend_from_slice(&25u16.to_be_bytes());
        resp.extend_from_slice(&3600u32.to_be_bytes());
        assert_eq!(natpmp_parse_map_response(&resp), Some((2525, 25, 3600)));

        // Error result code rejected.
        let mut bad = resp.clone();
        bad[2] = 0;
        bad[3] = 2;
        assert_eq!(natpmp_parse_map_response(&bad), None);
    }

    #[test]
    fn natpmp_ext_addr_parse() {
        let resp = [0u8, 128, 0, 0, 0, 0, 0, 0, 203, 0, 113, 5];
        assert_eq!(
            natpmp_parse_ext_addr(&resp),
            Some(Ipv4Addr::new(203, 0, 113, 5))
        );
        // Wrong opcode.
        let bad = [0u8, 129, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1];
        assert_eq!(natpmp_parse_ext_addr(&bad), None);
    }

    #[test]
    fn linux_default_gateway_parse() {
        // Iface Destination Gateway ... ; gateway 0101A8C0 = 192.168.1.1 (LE).
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(
            parse_linux_default_gateway(route),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        // No default route.
        let none = "Iface\tDestination\tGateway\n eth0\t0001A8C0\t00000000\n";
        assert_eq!(parse_linux_default_gateway(none), None);
    }

    #[test]
    fn ssdp_location_extraction() {
        let resp = "HTTP/1.1 200 OK\r\n\
                    CACHE-CONTROL: max-age=120\r\n\
                    LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
                    ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(resp).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
    }

    #[test]
    fn control_url_and_service_type() {
        let xml = "<root><device><serviceList>\
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl/IPConn</controlURL></service>\
            </serviceList></device></root>";
        let (ctrl, st) = parse_control_url(xml).unwrap();
        assert_eq!(ctrl, "/ctl/IPConn");
        assert!(st.contains("WANIPConnection"));
    }

    #[test]
    fn soap_external_ip_parse() {
        let resp = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
            <NewExternalIPAddress>81.2.3.4</NewExternalIPAddress>\
            </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(parse_soap_external_ip(resp).as_deref(), Some("81.2.3.4"));
        assert_eq!(parse_soap_external_ip("<x></x>"), None);
    }

    #[test]
    fn http_url_split() {
        assert_eq!(
            split_http_url("http://192.168.1.1:5000/rootDesc.xml"),
            Some(("192.168.1.1".into(), 5000, "/rootDesc.xml".into()))
        );
        assert_eq!(
            split_http_url("http://10.0.0.1/desc"),
            Some(("10.0.0.1".into(), 80, "/desc".into()))
        );
        assert_eq!(split_http_url("https://x/y"), None);
    }

    #[test]
    fn port_extraction() {
        assert_eq!(port_of("0.0.0.0:8080"), Some(8080));
        assert_eq!(port_of("127.0.0.1:25"), Some(25));
        assert_eq!(port_of("[::]:993"), Some(993));
        assert_eq!(port_of("nope"), None);
    }

    #[test]
    fn access_public_ip_is_reachable() {
        let res = MapResult {
            external_ip: Some("8.8.8.8".into()),
            method: Some("upnp"),
            mapped_ports: vec![8080, 25],
            failed_ports: vec![],
        };
        let pa = build_access(&res, 8080, false, Some("http://192.168.1.50:8080".into()));
        assert!(pa.reachable);
        assert_eq!(pa.url.as_deref(), Some("http://8.8.8.8.sslip.io:8080"));
        assert_eq!(pa.ip_url.as_deref(), Some("http://8.8.8.8:8080"));
    }

    #[test]
    fn access_cgnat_wan_is_not_reachable() {
        let res = MapResult {
            external_ip: Some("100.70.1.2".into()), // CGNAT
            method: Some("natpmp"),
            mapped_ports: vec![8080],
            failed_ports: vec![],
        };
        let pa = build_access(&res, 8080, false, Some("http://192.168.1.50:8080".into()));
        assert!(!pa.reachable);
        assert!(pa.url.is_none());
        assert!(pa.note.to_lowercase().contains("carrier-grade nat"));
        assert_eq!(pa.lan_url.as_deref(), Some("http://192.168.1.50:8080"));
    }

    #[test]
    fn access_no_router_falls_back_to_lan() {
        let res = MapResult::default();
        let pa = build_access(&res, 443, true, Some("https://10.0.0.9".into()));
        assert!(!pa.reachable);
        assert!(pa.note.to_lowercase().contains("manually") || pa.note.to_lowercase().contains("public_url"));
        assert_eq!(pa.lan_url.as_deref(), Some("https://10.0.0.9"));
    }

    #[test]
    fn add_port_mapping_body_shape() {
        let b = soap_add_port_mapping_body(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            8080,
            8080,
            "192.168.1.50",
            3600,
        );
        assert!(b.contains("<NewExternalPort>8080</NewExternalPort>"));
        assert!(b.contains("<NewInternalClient>192.168.1.50</NewInternalClient>"));
        assert!(b.contains("<NewLeaseDuration>3600</NewLeaseDuration>"));
        assert!(b.contains("AddPortMapping"));
    }
}
