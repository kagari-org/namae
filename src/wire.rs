use std::io;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

const MAGIC: [u8; 2] = *b"NM";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const MAC_LEN: usize = 32;
pub const MAX_FRAME: usize = 1024 * 1024;
pub const MAX_HANDSHAKE: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("bad magic/version")]
    BadHeader,
    #[error("frame too large: {0}")]
    FrameTooLarge(usize),
    #[error("bad mac")]
    BadMac,
    #[error("replayed or out-of-order frame")]
    Replay,
    #[error("invalid handshake")]
    Handshake,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error")]
    Crypto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Snapshot = 1,
    Delta = 2,
    Heartbeat = 3,
    Digest = 4,
    SyncRequest = 5,
    Ping = 6,
    Pong = 7,
}

impl FrameKind {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Snapshot,
            2 => Self::Delta,
            3 => Self::Heartbeat,
            4 => Self::Digest,
            5 => Self::SyncRequest,
            6 => Self::Ping,
            7 => Self::Pong,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: FrameKind,
    pub seq: u64,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity {
    pub node_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientHello {
    v: u8,
    node_id: u64,
    nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerHello {
    v: u8,
    node_id: u64,
    nonce: [u8; 32],
    mac: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientAuth {
    mac: [u8; 32],
}

pub struct SecureStream<S> {
    io: S,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: u64,
    recv_seq: u64,
}

pub struct SecureReader<S> {
    io: S,
    key: [u8; 32],
    seq: u64,
}

pub struct SecureWriter<S> {
    io: S,
    key: [u8; 32],
    seq: u64,
}

impl<S> Drop for SecureReader<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S> Drop for SecureWriter<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureStream<S> {
    pub fn split(
        self,
    ) -> (
        SecureReader<tokio::io::ReadHalf<S>>,
        SecureWriter<tokio::io::WriteHalf<S>>,
    ) {
        let (read, write) = tokio::io::split(self.io);
        (
            SecureReader {
                io: read,
                key: self.recv_key,
                seq: self.recv_seq,
            },
            SecureWriter {
                io: write,
                key: self.send_key,
                seq: self.send_seq,
            },
        )
    }
    pub async fn send(&mut self, kind: FrameKind, body: &[u8]) -> Result<(), WireError> {
        if body.len() > MAX_FRAME {
            return Err(WireError::FrameTooLarge(body.len()));
        }
        self.send_seq = self.send_seq.wrapping_add(1);
        let seq = self.send_seq;
        let mut header = [0u8; HEADER_LEN];
        header[..2].copy_from_slice(&MAGIC);
        header[2] = VERSION;
        header[3] = kind as u8;
        header[4..12].copy_from_slice(&seq.to_be_bytes());
        header[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        let mac = frame_mac(&self.send_key, &header, body)?;
        self.io.write_all(&header).await?;
        self.io.write_all(body).await?;
        self.io.write_all(&mac).await?;
        self.io.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Frame, WireError> {
        let mut header = [0u8; HEADER_LEN];
        self.io.read_exact(&mut header).await?;
        if header[..2] != MAGIC || header[2] != VERSION {
            return Err(WireError::BadHeader);
        }
        let kind = FrameKind::from_u8(header[3]).ok_or(WireError::BadHeader)?;
        let seq = u64::from_be_bytes(header[4..12].try_into().unwrap());
        let len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(WireError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len];
        self.io.read_exact(&mut body).await?;
        let mut mac = [0u8; MAC_LEN];
        self.io.read_exact(&mut mac).await?;
        let expected = frame_mac(&self.recv_key, &header, &body)?;
        if expected.ct_eq(&mac).unwrap_u8() != 1 {
            return Err(WireError::BadMac);
        }
        if seq <= self.recv_seq {
            return Err(WireError::Replay);
        }
        self.recv_seq = seq;
        Ok(Frame { kind, seq, body })
    }
}

impl<S: AsyncRead + Unpin> SecureReader<S> {
    pub async fn recv(&mut self) -> Result<Frame, WireError> {
        let mut header = [0u8; HEADER_LEN];
        self.io.read_exact(&mut header).await?;
        if header[..2] != MAGIC || header[2] != VERSION {
            return Err(WireError::BadHeader);
        }
        let kind = FrameKind::from_u8(header[3]).ok_or(WireError::BadHeader)?;
        let seq = u64::from_be_bytes(header[4..12].try_into().unwrap());
        let len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(WireError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len];
        self.io.read_exact(&mut body).await?;
        let mut mac = [0u8; MAC_LEN];
        self.io.read_exact(&mut mac).await?;
        let expected = frame_mac(&self.key, &header, &body)?;
        if expected.ct_eq(&mac).unwrap_u8() != 1 {
            return Err(WireError::BadMac);
        }
        if seq <= self.seq {
            return Err(WireError::Replay);
        }
        self.seq = seq;
        Ok(Frame { kind, seq, body })
    }
}

impl<S: AsyncWrite + Unpin> SecureWriter<S> {
    pub async fn send(&mut self, kind: FrameKind, body: &[u8]) -> Result<(), WireError> {
        if body.len() > MAX_FRAME {
            return Err(WireError::FrameTooLarge(body.len()));
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let mut header = [0u8; HEADER_LEN];
        header[..2].copy_from_slice(&MAGIC);
        header[2] = VERSION;
        header[3] = kind as u8;
        header[4..12].copy_from_slice(&seq.to_be_bytes());
        header[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        let mac = frame_mac(&self.key, &header, body)?;
        self.io.write_all(&header).await?;
        self.io.write_all(body).await?;
        self.io.write_all(&mac).await?;
        self.io.flush().await?;
        Ok(())
    }
}

fn frame_mac(key: &[u8; 32], header: &[u8], body: &[u8]) -> Result<[u8; 32], WireError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| WireError::Crypto)?;
    mac.update(header);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn handshake_mac(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], WireError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WireError::Crypto)?;
    mac.update(label);
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn derive_key(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], WireError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key).map_err(|_| WireError::Crypto)?;
    Ok(key)
}

async fn write_plain<S: AsyncWrite + Unpin>(io: &mut S, value: &[u8]) -> Result<(), WireError> {
    if value.len() > MAX_HANDSHAKE {
        return Err(WireError::FrameTooLarge(value.len()));
    }
    io.write_all(&(value.len() as u32).to_be_bytes()).await?;
    io.write_all(value).await?;
    io.flush().await?;
    Ok(())
}

async fn read_plain<S: AsyncRead + Unpin>(io: &mut S) -> Result<Vec<u8>, WireError> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_HANDSHAKE {
        return Err(WireError::FrameTooLarge(len));
    }
    let mut value = vec![0u8; len];
    io.read_exact(&mut value).await?;
    Ok(value)
}

pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    secret: &[u8],
    node_id: u64,
) -> Result<(SecureStream<S>, PeerIdentity), WireError> {
    let mut nonce_c = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce_c);
    write_plain(
        &mut io,
        &serde_json::to_vec(&ClientHello {
            v: VERSION,
            node_id,
            nonce: nonce_c,
        })?,
    )
    .await?;

    let hello: ServerHello = serde_json::from_slice(&read_plain(&mut io).await?)?;
    if hello.v != VERSION {
        return Err(WireError::Handshake);
    }
    let expected = handshake_mac(
        secret,
        b"namae/1 server",
        &[
            &nonce_c,
            &hello.nonce,
            &node_id.to_be_bytes(),
            &hello.node_id.to_be_bytes(),
        ],
    )?;
    if expected.ct_eq(&hello.mac).unwrap_u8() != 1 {
        return Err(WireError::BadMac);
    }

    let mac_c = handshake_mac(
        secret,
        b"namae/1 client",
        &[
            &nonce_c,
            &hello.nonce,
            &node_id.to_be_bytes(),
            &hello.node_id.to_be_bytes(),
        ],
    )?;
    write_plain(&mut io, &serde_json::to_vec(&ClientAuth { mac: mac_c })?).await?;

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&nonce_c);
    salt[32..].copy_from_slice(&hello.nonce);
    let send_key = derive_key(secret, &salt, b"namae/1 c2s")?;
    let recv_key = derive_key(secret, &salt, b"namae/1 s2c")?;
    Ok((
        SecureStream {
            io,
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
        },
        PeerIdentity {
            node_id: hello.node_id,
        },
    ))
}

pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    secret: &[u8],
    node_id: u64,
) -> Result<(SecureStream<S>, PeerIdentity), WireError> {
    let hello: ClientHello = serde_json::from_slice(&read_plain(&mut io).await?)?;
    if hello.v != VERSION {
        return Err(WireError::Handshake);
    }
    let mut nonce_s = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce_s);
    let mac_s = handshake_mac(
        secret,
        b"namae/1 server",
        &[
            &hello.nonce,
            &nonce_s,
            &hello.node_id.to_be_bytes(),
            &node_id.to_be_bytes(),
        ],
    )?;
    write_plain(
        &mut io,
        &serde_json::to_vec(&ServerHello {
            v: VERSION,
            node_id,
            nonce: nonce_s,
            mac: mac_s,
        })?,
    )
    .await?;

    let auth: ClientAuth = serde_json::from_slice(&read_plain(&mut io).await?)?;
    let expected = handshake_mac(
        secret,
        b"namae/1 client",
        &[
            &hello.nonce,
            &nonce_s,
            &hello.node_id.to_be_bytes(),
            &node_id.to_be_bytes(),
        ],
    )?;
    if expected.ct_eq(&auth.mac).unwrap_u8() != 1 {
        return Err(WireError::BadMac);
    }

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&hello.nonce);
    salt[32..].copy_from_slice(&nonce_s);
    let send_key = derive_key(secret, &salt, b"namae/1 s2c")?;
    let recv_key = derive_key(secret, &salt, b"namae/1 c2s")?;
    Ok((
        SecureStream {
            io,
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
        },
        PeerIdentity {
            node_id: hello.node_id,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn handshake_and_frame_roundtrip() {
        let (client, server) = duplex(8192);
        let secret = b"test-secret";
        let server_task = tokio::spawn(async move {
            let (mut stream, peer) = server_handshake(server, secret, 2).await.unwrap();
            assert_eq!(peer.node_id, 1);
            let frame = stream.recv().await.unwrap();
            assert_eq!(frame.kind, FrameKind::Ping);
            assert_eq!(frame.body, b"hello");
            stream.send(FrameKind::Pong, b"world").await.unwrap();
        });
        let (mut stream, peer) = client_handshake(client, secret, 1).await.unwrap();
        assert_eq!(peer.node_id, 2);
        stream.send(FrameKind::Ping, b"hello").await.unwrap();
        let frame = stream.recv().await.unwrap();
        assert_eq!(frame.kind, FrameKind::Pong);
        assert_eq!(frame.body, b"world");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let (client, server) = duplex(8192);
        let server_task =
            tokio::spawn(async move { server_handshake(server, b"server-secret", 2).await });
        let result = client_handshake(client, b"client-secret", 1).await;
        assert!(result.is_err());
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tampered_frame_is_rejected() {
        let key = [9u8; 32];
        let (client, mut raw) = duplex(8192);
        let mut writer = SecureWriter {
            io: client,
            key,
            seq: 0,
        };
        writer.send(FrameKind::Ping, b"hello").await.unwrap();
        let mut bytes = vec![0u8; HEADER_LEN + 5 + MAC_LEN];
        raw.read_exact(&mut bytes).await.unwrap();
        bytes[HEADER_LEN] ^= 0xff;

        let (mut tampered_tx, tampered_rx) = duplex(8192);
        tampered_tx.write_all(&bytes).await.unwrap();
        let mut reader = SecureReader {
            io: tampered_rx,
            key,
            seq: 0,
        };
        assert!(matches!(reader.recv().await, Err(WireError::BadMac)));
    }

    #[tokio::test]
    async fn replayed_frame_is_rejected() {
        let key = [3u8; 32];
        let (client, mut raw) = duplex(8192);
        let mut writer = SecureWriter {
            io: client,
            key,
            seq: 0,
        };
        writer.send(FrameKind::Ping, b"hello").await.unwrap();
        let mut bytes = vec![0u8; HEADER_LEN + 5 + MAC_LEN];
        raw.read_exact(&mut bytes).await.unwrap();

        let (mut sender, receiver) = duplex(8192);
        sender.write_all(&bytes).await.unwrap();
        sender.write_all(&bytes).await.unwrap();
        let mut reader = SecureReader {
            io: receiver,
            key,
            seq: 0,
        };
        assert!(reader.recv().await.is_ok());
        assert!(matches!(reader.recv().await, Err(WireError::Replay)));
    }
}
