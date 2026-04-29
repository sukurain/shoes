use tokio::io::AsyncWriteExt;

const BENIGN_DISCONNECT_MESSAGES: &[&str] = &[
    "stream reset by peer",
    "connection reset by peer",
    "reset by peer",
    "broken pipe",
    "unexpected eof",
    "connection aborted",
    "connection closed",
    "application closed",
    "closed by peer",
    "stopped by peer",
];

#[inline]
#[allow(clippy::uninit_vec)]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

// a cancellable alternative to AsyncWriteExt::write_all
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}

pub fn is_benign_disconnect(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
    ) {
        return true;
    }

    if is_benign_disconnect_message(&err.to_string()) {
        return true;
    }

    let mut source = std::error::Error::source(err);
    while let Some(err) = source {
        if is_benign_disconnect_message(&err.to_string()) {
            return true;
        }
        source = std::error::Error::source(err);
    }

    false
}

fn is_benign_disconnect_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    BENIGN_DISCONNECT_MESSAGES
        .iter()
        .any(|pattern| message.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_benign_disconnect_by_error_kind() {
        assert!(is_benign_disconnect(&Error::new(
            ErrorKind::ConnectionReset,
            "connection reset by peer",
        )));
        assert!(is_benign_disconnect(&Error::new(
            ErrorKind::ConnectionAborted,
            "connection aborted",
        )));
        assert!(is_benign_disconnect(&Error::new(
            ErrorKind::BrokenPipe,
            "broken pipe",
        )));
        assert!(is_benign_disconnect(&Error::new(
            ErrorKind::UnexpectedEof,
            "early eof",
        )));
        assert!(is_benign_disconnect(&Error::new(
            ErrorKind::NotConnected,
            "not connected",
        )));
    }

    #[test]
    fn test_benign_disconnect_by_message() {
        assert!(is_benign_disconnect(&Error::other(
            "stream reset by peer: error 0",
        )));
        assert!(is_benign_disconnect(&Error::other(
            "quic connection error: application closed",
        )));
        assert!(is_benign_disconnect(&Error::other(
            "H3 stream write failed: stopped by peer",
        )));
    }

    #[test]
    fn test_real_errors_are_not_benign_disconnects() {
        assert!(!is_benign_disconnect(&Error::other(
            "authentication timeout",
        )));
        assert!(!is_benign_disconnect(&Error::other(
            "failed to resolve DNS",
        )));
        assert!(!is_benign_disconnect(&Error::other(
            "invalid certificate",
        )));
        assert!(!is_benign_disconnect(&Error::other(
            "failed to bind address",
        )));
    }
}
