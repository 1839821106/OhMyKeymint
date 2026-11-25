//! Experimental OMK-LOCAL framework-counter adapter. This is not a verified
//! biometric token and does not bind a fingerprint match to a payment challenge.
//! Keep it opt-in; missing, malformed, stale or unreadable evidence must fail closed.

use crate::platform::Platform;
use serde_json::Value;

const MAX_DUMP: usize = 512 * 1024;

/// Accept only complete FingerprintService JSON documents, never arbitrary
/// strings containing "accept". Counters belong to an Android user, not an app.
fn accepted_count(dump: &[u8], user: u32) -> Option<u32> {
    if dump.len() > MAX_DUMP {
        return None;
    }
    let mut cursor = 0;
    let mut total = 0u64;
    let mut found = false;
    while let Some(offset) = dump[cursor..].iter().position(|byte| *byte == b'{') {
        let start = cursor + offset;
        let mut documents =
            serde_json::Deserializer::from_slice(&dump[start..]).into_iter::<Value>();
        let Some(Ok(document)) = documents.next() else {
            // A malformed JSON candidate must not expose a nested valid fragment.
            return None;
        };
        cursor = start + documents.byte_offset();
        let Some(prints) = document.get("prints") else { continue };
        for entry in prints.as_array()? {
            if entry.get("id")?.as_u64()? != u64::from(user) {
                continue;
            }
            let plain = entry.get("accept")?.as_u64()?;
            let crypto = entry.get("acceptCrypto")?.as_u64()?;
            total = total.checked_add(plain)?.checked_add(crypto)?;
            found = true;
        }
    }
    found.then(|| u32::try_from(total).ok()).flatten()
}

/// Sample only in the root broker, never trust a value supplied by SoterServer.
pub fn snapshot(uid: u32) -> Option<Platform> {
    #[cfg(target_os = "android")]
    {
        android::snapshot(uid)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = uid;
        None
    }
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use std::{
        io::{self, Read},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    fn dump() -> io::Result<Vec<u8>> {
        let (mut reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        let stdout: OwnedFd = writer.into();
        let mut child = Command::new("/system/bin/dumpsys")
            .args(["-t", "1", "fingerprint"])
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::null())
            .spawn()?;
        let result = (|| {
            let started = Instant::now();
            let mut output = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                // Bound each pass as well as total bytes so a busy writer cannot
                // prevent the deadline and child-status checks from running.
                for _ in 0..16 {
                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            if child.try_wait()?.is_some_and(|status| status.success()) {
                                return Ok(output);
                            }
                            break;
                        }
                        Ok(size) => {
                            if output.len() + size > MAX_DUMP {
                                return Err(io::Error::other("fingerprint output limit"));
                            }
                            output.extend_from_slice(&buffer[..size]);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                if let Some(status) = child.try_wait()? {
                    if !status.success() {
                        return Err(io::Error::other("fingerprint dump failed"));
                    }
                    // Drain buffered bytes on the next pass before accepting EOF.
                }
                if started.elapsed() >= Duration::from_millis(1500) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "fingerprint dump timeout",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
        result
    }

    pub(super) fn snapshot(uid: u32) -> Option<Platform> {
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        let count = accepted_count(&dump().ok()?, uid / 100_000)?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let tag = u32::from_str_radix(boot.get(..8)?, 16).ok()? & 0x7fff_ffff;
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
            return None;
        }
        let millis = u64::try_from(now.tv_sec)
            .ok()?
            .checked_mul(1000)?
            .checked_add(u64::try_from(now.tv_nsec).ok()? / 1_000_000)?;
        Some(Platform {
            boot_ms: Some(millis),
            bio_mark: Some((u64::from(tag) << crate::platform::BOOT_TAG_SHIFT) | u64::from(count)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_scoped_to_android_user_and_include_crypto_matches() {
        let dump = br#"Fingerprint dump
{"service":"Fingerprint Manager","prints":[{"id":0,"accept":4,"acceptCrypto":2},{"id":10,"accept":50,"acceptCrypto":7}]}
Sensor 2
{"prints":[{"id":0,"accept":3,"acceptCrypto":1}]}"#;
        assert_eq!(accepted_count(dump, 0), Some(10));
        assert_eq!(accepted_count(dump, 10), Some(57));
        assert_eq!(accepted_count(dump, 11), None);
    }

    #[test]
    fn unreadable_partial_or_overflowing_counters_never_authorize() {
        for dump in [
            br#"Permission Denial"#.as_slice(),
            br#"{"prints":[]}"#,
            br#"{"prints":[{"id":0,"accept":1}]}"#,
            br#"{"prints":[{"id":0,"accept":-1,"acceptCrypto":0}]}"#,
            br#"{"prints":[{"id":0,"accept":"1","acceptCrypto":0}]}"#,
            br#"{"prints":[{"id":0,"accept":4294967295,"acceptCrypto":1}]}"#,
            br#"{"prints":[{"id":0,"accept":18446744073709551615,"acceptCrypto":1}]}"#,
            br#"{"broken": {"prints":[{"id":0,"accept":1,"acceptCrypto":0}]}"#,
        ] {
            assert_eq!(accepted_count(dump, 0), None);
        }
        assert_eq!(accepted_count(&vec![b' '; MAX_DUMP + 1], 0), None);
    }
}
