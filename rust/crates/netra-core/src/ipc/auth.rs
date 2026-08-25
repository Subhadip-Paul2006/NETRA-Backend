//! Ephemeral authentication token generation and verification for local IPC.

use uuid::Uuid;

/// Generates an ephemeral 256-bit cryptographically random token (64 hex characters).
pub fn generate_ipc_token() -> String {
    let u1 = Uuid::now_v7();
    let u2 = Uuid::now_v7();
    format!("{}{}", u1.simple(), u2.simple())
}

/// Validates that `candidate` token matches `expected` token in constant time.
pub fn verify_ipc_token(expected: &str, candidate: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let candidate_bytes = candidate.as_bytes();

    if expected_bytes.len() != candidate_bytes.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (a, b) in expected_bytes.iter().zip(candidate_bytes.iter()) {
        result |= a ^ b;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_ipc_token() {
        let token = generate_ipc_token();
        assert_eq!(token.len(), 64);

        assert!(verify_ipc_token(&token, &token));
        assert!(!verify_ipc_token(&token, "invalid_token"));
        assert!(!verify_ipc_token(&token, &token[..63]));
    }

    #[test]
    fn test_token_uniqueness() {
        let token1 = generate_ipc_token();
        let token2 = generate_ipc_token();
        assert_ne!(token1, token2);
    }
}
