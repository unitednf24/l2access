use anyhow::{bail, Result};
use std::ffi::{CStr, CString};
use std::sync::Mutex;

#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

// getspnam, getpwnam, and crypt all use process-global static buffers.
// Serialise all auth checks to prevent concurrent calls from corrupting each other.
static AUTH_LOCK: Mutex<()> = Mutex::new(());

/// Verify credentials using native Linux passwd/shadow resolution.
/// Exactly mimics OpenWrt/LuCI and standard PAM shadow fallbacks.
pub fn verify_credentials(username: &str, password: &str) -> Result<()> {
    if username.is_empty() {
        bail!("Empty username");
    }

    // Hold the lock for the entire function: getspnam, getpwnam, and crypt are
    // not thread-safe (static internal buffers); concurrent callers must be serialised.
    let _guard = AUTH_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("auth lock poisoned"))?;

    let c_username = CString::new(username)?;
    let mut hash_bytes: Vec<u8> = Vec::new();
    let mut found = false;

    unsafe {
        // LuCI standard: try getspnam first (requires root for /etc/shadow)
        let spwd = libc::getspnam(c_username.as_ptr());
        if !spwd.is_null() {
            found = true;
            // Copy immediately — the pointer is into a static buffer that the
            // next getspnam/crypt call may overwrite.
            hash_bytes = CStr::from_ptr((*spwd).sp_pwdp).to_bytes().to_vec();
        } else {
            // Fallback to getpwnam (world-readable, but only carries 'x' on
            // shadow-enabled systems)
            let pw = libc::getpwnam(c_username.as_ptr());
            if !pw.is_null() {
                found = true;
                hash_bytes = CStr::from_ptr((*pw).pw_passwd).to_bytes().to_vec();
            }
        }
    }

    if !found {
        bail!("User not found or access denied (run as root)");
    }

    // Empty hash → account has no password set (common on OpenWrt root).
    if hash_bytes.is_empty() {
        return if password.is_empty() {
            Ok(())
        } else {
            bail!(
                "Password was provided (len {}) for an account that expects no password",
                password.len()
            )
        };
    }

    // 'x' means the real hash is in /etc/shadow but getspnam failed (not root).
    if hash_bytes == b"x" {
        bail!("Account restricted: shadow hash inaccessible (run server as root)");
    }
    // '!' or '*' → account locked.
    if hash_bytes.starts_with(b"!") || hash_bytes.starts_with(b"*") {
        bail!("Account locked in /etc/shadow or /etc/passwd");
    }

    let c_password = CString::new(password)?;
    // Build a NUL-terminated copy of the hash to use as the crypt salt.
    // hash_bytes was already copied above, so this doesn't alias the getspnam buffer.
    let c_hash = CString::new(hash_bytes.clone())
        .map_err(|_| anyhow::anyhow!("stored hash contains an unexpected NUL byte"))?;

    let crypt_res = unsafe { crypt(c_password.as_ptr(), c_hash.as_ptr()) };
    if crypt_res.is_null() {
        bail!("crypt() returned NULL (unsupported hash scheme?)");
    }

    let computed = unsafe { CStr::from_ptr(crypt_res).to_bytes() };

    if hash_bytes.as_slice() == computed {
        Ok(())
    } else {
        bail!("Invalid credentials")
    }
}

/// Serialize credentials for encrypted transport: `<user>\0<pass>`.
pub fn encode_credentials(username: &str, password: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(username.len() + 1 + password.len());
    v.extend_from_slice(username.as_bytes());
    v.push(0);
    v.extend_from_slice(password.as_bytes());
    v
}

/// Deserialize credentials from `<user>\0<pass>`.
pub fn decode_credentials(data: &[u8]) -> Result<(String, String)> {
    let pos = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("malformed credentials"))?;
    let username = std::str::from_utf8(&data[..pos])
        .map_err(|e| anyhow::anyhow!("username utf8: {}", e))?
        .to_string();
    let password = std::str::from_utf8(&data[pos + 1..])
        .map_err(|e| anyhow::anyhow!("password utf8: {}", e))?
        .to_string();
    if username.is_empty() {
        bail!("empty username");
    }
    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let encoded = encode_credentials("alice", "secret123");
        let (u, p) = decode_credentials(&encoded).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(p, "secret123");
    }

    #[test]
    #[ignore]
    fn test_verify_credentials() {
        // This test requires root access to read /etc/shadow
        assert!(verify_credentials("bob", "pass").is_ok());
        assert!(verify_credentials("", "pass").is_err());
        assert!(verify_credentials("bob", "").is_err());
    }
}
