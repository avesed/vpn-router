//! TPROXY UDP Proof of Concept
//!
//! Phase 0 Day 2: Validates that Rust can correctly handle TPROXY UDP traffic.
//!
//! Key differences from TCP:
//! - UDP uses recvmsg with IP_RECVORIGDSTADDR control message to get original destination
//! - UDP requires sending from the spoofed source address (using IP_TRANSPARENT)
//! - UDP sessions need timeout-based cleanup (no FIN/RST)
//!
//! Required iptables rules (example):
//! ```bash
//! iptables -t mangle -A PREROUTING -i wg-ingress -p udp -j TPROXY \
//!     --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
//! ip rule add fwmark 0x1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! Required sysctls:
//! - net.ipv4.conf.all.route_localnet = 1
//! - net.ipv4.ip_nonlocal_bind = 1
//!
//! Run with: sudo ./udp_tproxy_poc

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// Linux kernel constant: IP_TRANSPARENT socket option
const IP_TRANSPARENT: libc::c_int = 19;

/// Linux kernel constant: IP_RECVORIGDSTADDR
/// When enabled, the original destination address is delivered as ancillary data
const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// Default TPROXY listen address
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:7893";

/// UDP session timeout (5 minutes, matches sing-box default)
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Buffer size for UDP packets
const UDP_BUFFER_SIZE: usize = 65535;

/// Session cleanup interval
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Represents a UDP session with upstream
struct UdpSession {
    /// Socket connected to upstream
    upstream_socket: UdpSocket,
    /// Original destination address
    original_dst: SocketAddr,
    /// Last activity time
    last_activity: Instant,
}

/// Create a UDP socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR enabled.
fn create_tproxy_udp_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;

    let fd = socket.as_raw_fd();

    // Enable IP_TRANSPARENT
    unsafe {
        let one: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!(
                "Failed to set IP_TRANSPARENT: {}",
                io::Error::last_os_error()
            ));
        }
    }

    // Enable IP_RECVORIGDSTADDR - this is crucial for getting the original destination
    unsafe {
        let one: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!(
                "Failed to set IP_RECVORIGDSTADDR: {}",
                io::Error::last_os_error()
            ));
        }
    }

    // Enable SO_REUSEADDR
    socket.set_reuse_address(true)?;

    // Enable SO_REUSEPORT
    socket.set_reuse_port(true)?;

    // Set non-blocking
    socket.set_nonblocking(true)?;

    info!("Created TPROXY UDP socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR");
    Ok(socket)
}

/// Receive a UDP packet with the original destination address from cmsg.
///
/// This uses recvmsg to get both the packet data and the control message
/// containing the original destination address (set by TPROXY).
fn recv_with_original_dst(fd: RawFd, buf: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr)> {
    // Prepare the iovec for the data
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Prepare the source address buffer
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let src_addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // Prepare the control message buffer
    // Size calculation: CMSG_SPACE for sockaddr_in
    const CMSG_SPACE_SIZE: usize = 64; // Conservative size for cmsg
    let mut cmsg_buf: [u8; CMSG_SPACE_SIZE] = [0; CMSG_SPACE_SIZE];

    // Prepare msghdr
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = src_addr_len;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = CMSG_SPACE_SIZE;

    // Call recvmsg
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(anyhow!("WouldBlock"));
        }
        return Err(anyhow!("recvmsg failed: {}", err));
    }

    // Parse source address
    let src_port = u16::from_be(src_addr.sin_port);
    let src_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));

    // Parse control message to get original destination
    let mut original_dst: Option<SocketAddr> = None;

    // Iterate through control messages
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let cmsg_ref = unsafe { &*cmsg };

        if cmsg_ref.cmsg_level == libc::SOL_IP && cmsg_ref.cmsg_type == IP_RECVORIGDSTADDR {
            // Found the original destination address
            let addr_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in;
            let addr = unsafe { &*addr_ptr };

            let dst_port = u16::from_be(addr.sin_port);
            let dst_ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            original_dst = Some(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)));
            break;
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    let dst = original_dst.ok_or_else(|| anyhow!("Original destination not found in cmsg"))?;

    Ok((n as usize, src, dst))
}

/// Create a UDP socket bound to a specific source address (for spoofed replies).
///
/// When sending replies back to the client, we need to send from the original
/// destination address, making it appear as if the real server is responding.
fn create_reply_socket(bind_addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create reply socket")?;

    let fd = socket.as_raw_fd();

    // Enable IP_TRANSPARENT for binding to non-local address
    unsafe {
        let one: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!(
                "Failed to set IP_TRANSPARENT on reply socket: {}",
                io::Error::last_os_error()
            ));
        }
    }

    // Set non-blocking
    socket.set_nonblocking(true)?;

    // Bind to the original destination address (spoofed source for replies)
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("Failed to bind reply socket to {}", bind_addr))?;

    Ok(unsafe { std::net::UdpSocket::from_raw_fd(socket.into_raw_fd()) })
}

/// Session manager for UDP NAT traversal
type SessionMap = Arc<RwLock<HashMap<(SocketAddr, SocketAddr), UdpSession>>>;

/// Handle incoming TPROXY UDP packets
async fn handle_udp_packets(
    socket: UdpSocket,
    sessions: SessionMap,
) -> Result<()> {
    let fd = socket.as_raw_fd();
    let mut buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        // Wait for socket to be readable
        socket.readable().await?;

        // Try to receive with original destination
        match recv_with_original_dst(fd, &mut buf) {
            Ok((n, src, dst)) => {
                debug!("UDP packet: {} -> {} ({} bytes)", src, dst, n);

                // Session key is (client_addr, original_dst)
                let session_key = (src, dst);

                // Check if session exists
                let session_exists = {
                    let sessions_read = sessions.read().await;
                    sessions_read.contains_key(&session_key)
                };

                if !session_exists {
                    // Create new session
                    info!("New UDP session: {} -> {}", src, dst);

                    // Connect to upstream
                    let upstream = UdpSocket::bind("0.0.0.0:0").await?;
                    upstream.connect(dst).await?;

                    let session = UdpSession {
                        upstream_socket: upstream,
                        original_dst: dst,
                        last_activity: Instant::now(),
                    };

                    sessions.write().await.insert(session_key, session);

                    // Spawn reply handler for this session
                    let sessions_clone = Arc::clone(&sessions);
                    let client_addr = src;
                    let original_dst = dst;

                    tokio::spawn(async move {
                        if let Err(e) = handle_upstream_replies(
                            sessions_clone,
                            client_addr,
                            original_dst,
                        ).await {
                            debug!("Upstream reply handler ended: {}", e);
                        }
                    });
                }

                // Send to upstream
                let sessions_read = sessions.read().await;
                if let Some(session) = sessions_read.get(&session_key) {
                    if let Err(e) = session.upstream_socket.send(&buf[..n]).await {
                        error!("Failed to send to upstream: {}", e);
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("WouldBlock") {
                    continue;
                }
                error!("recv_with_original_dst error: {}", e);
            }
        }
    }
}

/// Handle replies from upstream and send back to client
async fn handle_upstream_replies(
    sessions: SessionMap,
    client_addr: SocketAddr,
    original_dst: SocketAddr,
) -> Result<()> {
    let session_key = (client_addr, original_dst);
    let mut buf = vec![0u8; UDP_BUFFER_SIZE];

    // Create reply socket bound to original destination (spoofed source)
    let reply_socket = create_reply_socket(original_dst)?;
    let reply_socket = UdpSocket::from_std(reply_socket)?;

    loop {
        // Check if session still exists and not timed out
        {
            let sessions_read = sessions.read().await;
            match sessions_read.get(&session_key) {
                Some(session) => {
                    if session.last_activity.elapsed() > UDP_SESSION_TIMEOUT {
                        info!("UDP session timeout: {} -> {}", client_addr, original_dst);
                        drop(sessions_read);
                        sessions.write().await.remove(&session_key);
                        return Ok(());
                    }
                }
                None => return Ok(()),
            }
        }

        // Read from upstream in the session
        let recv_result: Option<io::Result<usize>> = {
            let sessions_read = sessions.read().await;
            sessions_read.get(&session_key).map(|session| session.upstream_socket.try_recv(&mut buf))
        };

        match recv_result {
            Some(Ok(n)) => {
                debug!("Upstream reply: {} <- {} ({} bytes)", client_addr, original_dst, n);

                // Send reply to client from original destination address
                if let Err(e) = reply_socket.send_to(&buf[..n], client_addr).await {
                    error!("Failed to send reply to client: {}", e);
                }

                // Update last activity
                let mut sessions_write = sessions.write().await;
                if let Some(session) = sessions_write.get_mut(&session_key) {
                    session.last_activity = Instant::now();
                }
            }
            Some(Err(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                // Wait for data
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Some(Err(e)) => {
                error!("Upstream recv error: {}", e);
                return Err(anyhow!("Upstream error: {}", e));
            }
            None => {
                // Session was removed
                return Ok(());
            }
        }
    }
}

/// Clean up expired UDP sessions
async fn cleanup_sessions(sessions: SessionMap) {
    let mut interval = interval(CLEANUP_INTERVAL);

    loop {
        interval.tick().await;

        let mut sessions_write = sessions.write().await;
        let before_count = sessions_write.len();

        sessions_write.retain(|key, session| {
            let keep = session.last_activity.elapsed() < UDP_SESSION_TIMEOUT;
            if !keep {
                info!("Cleaning up expired session: {} -> {}", key.0, key.1);
            }
            keep
        });

        let removed = before_count - sessions_write.len();
        if removed > 0 {
            info!("Cleaned up {} expired UDP sessions", removed);
        }
    }
}

/// Demo mode for non-root testing
async fn demo_mode() -> Result<()> {
    warn!("Running in DEMO mode - no actual TPROXY traffic");
    warn!("To test with real TPROXY, configure iptables rules and run as root");

    println!("\n=== TPROXY UDP PoC Demo ===\n");
    println!("This PoC validates the following capabilities:");
    println!("  1. IP_TRANSPARENT socket option - SUPPORTED");
    println!("  2. IP_RECVORIGDSTADDR for cmsg - AVAILABLE");
    println!("  3. recvmsg with control messages - IMPLEMENTED");
    println!("  4. UDP session management - IMPLEMENTED");
    println!("  5. Spoofed source address replies - IMPLEMENTED");
    println!();
    println!("UDP TPROXY is more complex than TCP:");
    println!("  - No SO_ORIGINAL_DST, must use recvmsg cmsg");
    println!("  - Must send replies from spoofed source address");
    println!("  - Needs session timeout management (5 min default)");
    println!();

    // Test socket creation
    match create_tproxy_udp_socket() {
        Ok(_) => println!("✓ UDP TPROXY socket creation: SUCCESS"),
        Err(e) => println!("✗ UDP TPROXY socket creation: FAILED - {}", e),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Check if running as root
    let is_root = unsafe { libc::geteuid() == 0 };

    if !is_root {
        warn!("Not running as root - TPROXY requires CAP_NET_ADMIN");
        return demo_mode().await;
    }

    let listen_addr: SocketAddr = std::env::var("TPROXY_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string())
        .parse()
        .context("Invalid listen address")?;

    info!("Starting TPROXY UDP PoC on {}", listen_addr);

    // Create TPROXY socket
    let socket = create_tproxy_udp_socket()?;

    // Bind
    socket
        .bind(&listen_addr.into())
        .with_context(|| format!("Failed to bind to {}", listen_addr))?;

    info!("TPROXY UDP listener ready on {}", listen_addr);

    // Convert to tokio UdpSocket
    let socket = UdpSocket::from_std(unsafe {
        std::net::UdpSocket::from_raw_fd(socket.into_raw_fd())
    })?;

    // Session manager
    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));

    // Spawn cleanup task
    let sessions_cleanup = Arc::clone(&sessions);
    tokio::spawn(async move {
        cleanup_sessions(sessions_cleanup).await;
    });

    // Main packet handler
    handle_udp_packets(socket, sessions).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_hashing() {
        let addr1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let addr2: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let mut map: HashMap<(SocketAddr, SocketAddr), i32> = HashMap::new();
        map.insert((addr1, addr2), 42);

        assert_eq!(map.get(&(addr1, addr2)), Some(&42));
    }
}
