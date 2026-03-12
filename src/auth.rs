use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Verify credentials using native Linux passwd/shadow resolution.
/// Exactly mimics OpenWrt/LuCI and standard PAM shadow fallbacks.
pub fn verify_credentials(username: &str, password: &str) -> Result<()> {
    if username.is_empty() {
        bail!("Empty username");
    }

    let c_username = CString::new(username)?;
    let mut hash_ptr: *const libc::c_char = std::ptr::null();

    unsafe {
        // LuCI standard: try getspnam first
        let spwd = libc::getspnam(c_username.as_ptr());
        if !spwd.is_null() {
            hash_ptr = (*spwd).sp_pwdp;
        } else {
            // fallback to getpwnam
            let pw = libc::getpwnam(c_username.as_ptr());
            if !pw.is_null() {
                hash_ptr = (*pw).pw_passwd;
            }
        }
    }

    if hash_ptr.is_null() {
        bail!("User not found or access denied (run as root)");
    }

    let hash_cstr = unsafe { CStr::from_ptr(hash_ptr) };
    let hash_bytes = hash_cstr.to_bytes();

    // If the retrieved hash is completely empty, it means "no password required".
    // This happens frequently on OpenWrt for the default 'root' user.
    if hash_bytes.is_empty() {
        if password.is_empty() {
            return Ok(());
        } else {
            bail!(
                "Password was provided (len {}) for an account that expects no password",
                password.len()
            );
        }
    }

    // Passwords starting with '!' or '*' are locked accounts in /etc/shadow or /etc/passwd.
    if hash_bytes == b"x" {
        bail!("Account restricted: hash is 'x' (Shadow lookup failed. Are you running the server as root?)");
    }
    if hash_bytes.starts_with(b"!") || hash_bytes.starts_with(b"*") {
        bail!("Account locked in /etc/shadow or /etc/passwd (hash restricted)");
    }

    let c_password = CString::new(password)?;

    // Call crypt to hash the input password with the salt from the system hash
    let crypt_res = unsafe { crypt(c_password.as_ptr(), hash_ptr) };
    if crypt_res.is_null() {
        bail!(
            "Failed to generate crypt hash from salt length {}",
            hash_bytes.len()
        );
    }

    let computed_hash = unsafe { CStr::from_ptr(crypt_res) };

    // Standard string comparison
    if hash_bytes == computed_hash.to_bytes() {
        Ok(())
    } else {
        bail!("Invalid credentials (password crypt hash mismatch)");
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
