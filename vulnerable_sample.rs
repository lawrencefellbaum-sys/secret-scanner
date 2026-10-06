//! Synthetic test target for static analysis security scanner.
//! WARNING: This file contains intentional vulnerabilities for scanning tests.

use std::net::UdpSocket;
use std::slice;

// ============================================================================
// 1. HARDCODED API KEYS & SECRETS
// ============================================================================

/// Simulated hardcoded API credentials.
pub struct SecretConfig {
    pub aws_key: &'static str,
    pub openai_key: &'static str,
    pub github_token: &'static str,
    pub jwt_token: &'static str,
}

pub fn get_credentials() -> SecretConfig {
    SecretConfig {
        // Hardcoded AWS Access Key ID pattern
        aws_key: "AKIAIOSFODNN7EXAMPLE",
        // Hardcoded OpenAI Secret Key pattern
        openai_key: "sk-proj-abc123456789012345678901234567890123456789012345",
        // Hardcoded GitHub Personal Access Token pattern
        github_token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456",
        // Hardcoded JSON Web Token pattern
        jwt_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }
}

// ============================================================================
// 2. RUST UNSAFE CODE BLOCKS & MEMORY SAFETY RISKS
// ============================================================================

/// Raw pointer dereferencing inside an unsafe block.
pub fn read_raw_memory(ptr: *const u8, len: usize) -> Vec<u8> {
    // Unsafe block: direct pointer dereferencing and slice creation
    unsafe {
        let slice = slice::from_raw_parts(ptr, len);
        slice.to_vec()
    }
}

/// Unsafe block performing unchecked memory access and type conversion.
pub fn transmute_buffer(data: &[u8]) -> &'static str {
    unsafe {
        // Circumventing Rust's borrow checker and type system
        std::mem::transmute(data)
    }
}

// ============================================================================
// 3. DOS PACKET INJECTION & UNBOUNDED BUFFER ALLOCATIONS
// ============================================================================

/// Parses network packet headers without validating payload lengths,
/// leading to potential Denial of Service (DoS) / unbounded memory allocation.
pub fn process_incoming_packet(socket: &UdpSocket) {
    let mut header_buf = [0u8; 8];
    if socket.recv(&mut header_buf).is_ok() {
        // Extract unvalidated length header directly from packet payload
        let declared_length = u32::from_be_bytes([
            header_buf[0],
            header_buf[1],
            header_buf[2],
            header_buf[3],
        ]) as usize;

        // VULNERABILITY (DoS): Allocating unbounded memory directly from network input.
        // A malicious packet specifying `declared_length = 4GB` causes immediate OOM crash.
        let mut packet_buffer: Vec<u8> = Vec::with_capacity(declared_length);
        
        // Unvalidated packet loop reading directly into packet buffer
        loop {
            let mut chunk = [0u8; 1024];
            match socket.recv(&mut chunk) {
                Ok(bytes_read) => {
                    packet_buffer.extend_from_slice(&chunk[..bytes_read]);
                    if packet_buffer.len() >= declared_length {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn main() {
    let creds = get_credentials();
    println!("Loaded AWS key: {}", creds.aws_key);

    let dummy_data = [65u8, 66u8, 67u8];
    let _mem = read_raw_memory(dummy_data.as_ptr(), dummy_data.len());
}