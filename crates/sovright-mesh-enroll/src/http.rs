//! Minimal HTTP/1.1 request/response framing for the PoC binaries.
//!
//! Not a general HTTP implementation — just enough to POST a JSON body to the
//! enroll endpoint over a single loopback connection, with no external deps.
//! Production terminates TLS and uses a real HTTP stack; the parsing here is
//! pure + unit-tested, and the tiny std-TCP I/O wraps it.

use std::io::{Read, Write};
use std::net::TcpStream;

/// Parsed request line + framing metadata (headers we care about).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub content_length: usize,
}

/// Parse the request head (everything up to the blank line). Returns the head
/// and the number of bytes consumed (so the caller can find the body start).
pub fn parse_request_head(buf: &[u8]) -> Option<(RequestHead, usize)> {
    let sep = b"\r\n\r\n";
    let end = buf.windows(4).position(|w| w == sep)? + 4;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    Some((
        RequestHead {
            method,
            path,
            content_length,
        },
        end,
    ))
}

/// Build a full HTTP/1.1 response with a JSON body.
pub fn json_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

/// Read a full request (head + Content-Length body) from a stream.
pub fn read_request(stream: &mut TcpStream) -> std::io::Result<(RequestHead, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Read until we have the head.
    let (head, body_start) = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(parsed) = parse_request_head(&buf) {
            break parsed;
        }
        if buf.len() > 1 << 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    };
    // Read the rest of the body.
    let mut body = buf[body_start..].to_vec();
    while body.len() < head.content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(head.content_length);
    Ok((head, body))
}

/// POST a JSON body to `host:port` at `path` over a fresh TCP connection and
/// return `(status, body)`. PoC only — no TLS, no keep-alive, no redirects.
pub fn post_json(addr: &str, path: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    let host = addr.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_head_extracts_method_path_len() {
        let raw = b"POST /v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nbodybodybody";
        let (head, consumed) = parse_request_head(raw).unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/v1/enroll");
        assert_eq!(head.content_length, 12);
        assert_eq!(&raw[consumed..], b"bodybodybody");
    }

    #[test]
    fn parse_head_case_insensitive_length_and_missing_defaults_zero() {
        let raw = b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n";
        let (head, _) = parse_request_head(raw).unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.content_length, 0);
    }

    #[test]
    fn parse_head_incomplete_returns_none() {
        assert!(parse_request_head(b"POST /v1/enroll HTTP/1.1\r\nHost: x").is_none());
    }

    #[test]
    fn json_response_is_wellformed() {
        let r = json_response(200, "OK", "{\"ok\":true}");
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 11\r\n"));
        assert!(s.ends_with("\r\n\r\n{\"ok\":true}"));
    }
}
