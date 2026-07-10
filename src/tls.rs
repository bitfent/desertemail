//! rustls-based TLS: server Conn, client ClientConn, PEM loading.
//! Plain threads only — no async.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::util;

/// Server-side connection: plaintext TCP or rustls StreamOwned.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

impl Conn {
    pub fn is_tls(&self) -> bool {
        matches!(self, Conn::Tls(_))
    }

    pub fn peer_addr_string(&self) -> String {
        let stream = match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => s.get_ref(),
        };
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into())
    }

    pub fn set_timeouts(&self, dur: std::time::Duration) {
        let stream = match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => s.get_ref(),
        };
        let _ = stream.set_read_timeout(Some(dur));
        let _ = stream.set_write_timeout(Some(dur));
    }
}

/// Client-side connection for outbound SMTP (plain or TLS).
pub enum ClientConn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for ClientConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientConn::Plain(s) => s.read(buf),
            ClientConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ClientConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ClientConn::Plain(s) => s.write(buf),
            ClientConn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ClientConn::Plain(s) => s.flush(),
            ClientConn::Tls(s) => s.flush(),
        }
    }
}

impl ClientConn {
    pub fn into_plain(self) -> Option<TcpStream> {
        match self {
            ClientConn::Plain(s) => Some(s),
            ClientConn::Tls(_) => None,
        }
    }
}

/// Load PEM cert chain + private key (PKCS#8 or RSA) into a ServerConfig.
pub fn load_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(Path::new(cert_path))?;
    util::log!("TLS: loaded cert chain length {} from {}", certs.len(), cert_path);
    let key = load_private_key(Path::new(key_path))?;
    util::log!("TLS: loaded private key from {}", key_path);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS server config: {}", e))?;
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("open cert {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(f);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| format!("parse cert {}: {}", path.display(), e))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("open key {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(f);
    // rustls-pemfile 2.x: private_key() accepts PKCS#8, RSA, EC.
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key {}: {}", path.display(), e))?
        .ok_or_else(|| format!("no private key in {}", path.display()))?;
    Ok(key)
}

/// Implicit TLS: wrap the TCP stream; handshake completes on first I/O.
pub fn accept_tls(stream: TcpStream, cfg: &Arc<ServerConfig>) -> io::Result<Conn> {
    let conn = ServerConnection::new(Arc::clone(cfg))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS server conn: {}", e)))?;
    Ok(Conn::Tls(Box::new(StreamOwned::new(conn, stream))))
}

/// STARTTLS upgrade on an existing plaintext TCP stream.
/// Handshake completes on the next read/write after this returns.
pub fn upgrade(stream: TcpStream, cfg: &Arc<ServerConfig>) -> io::Result<Conn> {
    accept_tls(stream, cfg)
}

/// Outbound TLS with full certificate validation (webpki-roots).
/// On failure the caller should fall back to a fresh plaintext connection.
pub fn connect_tls(stream: TcpStream, server_name: &str) -> io::Result<ClientConn> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let name = ServerName::try_from(server_name.to_string()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid server name {:?}: {}", server_name, e),
        )
    })?;

    let conn = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS client conn: {}", e)))?;
    let mut tls = StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        match tls.conn.complete_io(&mut tls.sock) {
            Ok((0, 0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS handshake EOF (client)",
                ));
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ClientConn::Tls(Box::new(tls)))
}
