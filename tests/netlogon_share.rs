//! `NETLOGON` over real SMB, from a directory, with a real client.
//!
//! `SYSVOL` is a snapshot rendered from the policies; this share is not. A logon script is a file an
//! administrator edits and drops in, so the backend reads the directory live - and that difference is
//! the one thing here that a unit test on the backend would not prove, because it is a property of
//! the wiring: the same `LocalFsBackend` mounted at start, with a file written afterwards, has to
//! list that file without a restart.
//!
//! The rest is the same two-sided check the SYSVOL share gets, for the same reason: a download that
//! works says nothing about whether an anonymous client is refused, and a logon script is a file
//! that decides what runs in somebody's session.
//!
//! `smbclient` is a package, not a build dependency, and a machine without Samba should not fail
//! this repository's tests. Absent, the test says so and returns - and the run has to be read, not
//! counted: a skipped test is not a passing one.

#![cfg(feature = "smb")]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// An account the test server accepts: the share mode is about the logon, and a logon is needed.
const USER: &str = "alice";

/// Not a secret: this account exists for the length of one test, in a process nobody else reaches.
const PASSWORD: &str = "Pa55word!-for-one-test";

/// `smbclient`'s version, or `None` when Samba is not installed here.
fn smbclient() -> Option<String> {
    let output = Command::new("smbclient").arg("--version").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// One `smbclient` command against `share`, as `user` or anonymously, stdout and stderr together.
///
/// The port goes in `-p`, not in the UNC: `smbclient` reads `//host:port/share` as a host name and
/// fails at `getaddrinfo`, which is a confusing way to learn this.
fn run(port: u16, share: &str, user: Option<&str>, command: &str) -> (bool, String) {
    let mut invocation = Command::new("smbclient");
    invocation.arg(format!("//127.0.0.1/{share}")).args([
        "-p",
        &port.to_string(),
        "-m",
        "SMB3",
        "-c",
        command,
    ]);
    match user {
        Some(name) => {
            invocation.args(["-U", &format!("{name}%{PASSWORD}")]);
        }
        // `-N`: no password, so the session is anonymous.
        None => {
            invocation.arg("-N");
        }
    }
    let output = invocation.output().expect("smbclient runs");
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

/// A directory holding one logon script, removed when the test ends.
struct Scripts(std::path::PathBuf);

impl Scripts {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rrl-netlogon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory for the scripts");
        std::fs::write(dir.join("logon.bat"), b"@echo off\r\necho hello\r\n")
            .expect("a logon script");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scripts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Multi-threaded on purpose: the client is a blocking process, and on the default current-thread
// runtime its `wait` holds the only thread the SMB accept loop could run on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_client_reads_a_logon_script_and_a_new_one_appears_without_a_restart() {
    let Some(version) = smbclient() else {
        // A skip, except where a skip is the defect: CI installs `smbclient` and sets `CI`, so
        // there the absence is a failure rather than a green result that opened nothing.
        if std::env::var_os("CI").is_some() {
            panic!(
                "smbclient is not installed and CI is set: the NETLOGON test cannot be skipped \
                 here, because a skipped test that reports `ok` is how these tests proved nothing"
            );
        }
        eprintln!("skipping: smbclient is not installed, so nothing was proved about NETLOGON");
        return;
    };
    eprintln!("smbclient: {version}");

    let scripts = Scripts::new("read");
    let backend = smb_server::LocalFsBackend::new(scripts.path())
        .expect("the scripts directory opens as a share root");
    let share = smb_server::Share::new("NETLOGON", backend.read_only()).authenticated_read_only();

    let server = smb_server::SmbServer::builder()
        .listen((std::net::Ipv4Addr::LOCALHOST, 0).into())
        .netbios_name("DC1")
        .user(USER, PASSWORD)
        .share(share)
        .share_listing(false)
        .build()
        .expect("a server with one read-only share");
    let addr = server.bind().await.expect("a port the kernel picks");
    let task = tokio::spawn(server.serve());

    // Wait for the accept loop rather than for a duration: a fixed sleep fails on a loaded machine
    // and passes on an idle one, and names the client instead of the server.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if task.is_finished() {
            let outcome = task.await;
            panic!("the SMB accept loop ended before a client could reach it: {outcome:?}");
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "nothing accepted on {addr} within five seconds"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // The refusal first: a logon script says what runs in a session, and an anonymous client must
    // get none of it.
    let (ok, text) = run(addr.port(), "NETLOGON", None, "ls");
    assert!(
        !ok,
        "an anonymous client must not reach NETLOGON, and it said: {text}"
    );
    assert!(
        text.contains("NT_STATUS_ACCESS_DENIED") || text.contains("NT_STATUS_LOGON_FAILURE"),
        "and the refusal names a status: {text}"
    );

    // The listing: the script an administrator put there.
    let (ok, text) = run(addr.port(), "NETLOGON", Some(USER), "ls");
    assert!(ok, "a listing of the share root: {text}");
    assert!(
        text.contains("logon.bat"),
        "the listing names the script: {text}"
    );

    // The bytes: fetched, then compared with the file on disk. A listing that carries the right name
    // and a file that carries the wrong bytes would pass everything above.
    let destination = std::env::temp_dir().join(format!("rrl-netlogon-out-{}", std::process::id()));
    let _ = std::fs::remove_file(&destination);
    let (ok, text) = run(
        addr.port(),
        "NETLOGON",
        Some(USER),
        &format!(r#"get logon.bat "{}""#, destination.display()),
    );
    assert!(ok, "fetching the script: {text}");
    let fetched = std::fs::read(&destination).expect("the file the client wrote");
    let expected = std::fs::read(scripts.path().join("logon.bat")).expect("the same file on disk");
    assert_eq!(
        fetched, expected,
        "the bytes a client got are the bytes on disk"
    );
    let _ = std::fs::remove_file(&destination);

    // The property that separates this share from SYSVOL: a file written after the mount is listed
    // without a restart. A snapshot backend would fail here, and it would fail in production as a
    // script that "was not copied" until somebody restarted the controller.
    std::fs::write(
        scripts.path().join("second.bat"),
        b"@echo off\r\nrem second\r\n",
    )
    .expect("a second script, written while the share is mounted");
    let (ok, text) = run(addr.port(), "NETLOGON", Some(USER), "ls");
    assert!(ok, "the listing after a new file: {text}");
    assert!(
        text.contains("second.bat"),
        "a script added after the mount is listed without a restart: {text}"
    );

    // And the refusal to write: a logon script a domain member could replace is code that member
    // runs in somebody else's session.
    let source = std::env::temp_dir().join(format!("rrl-netlogon-put-{}", std::process::id()));
    std::fs::write(&source, b"should not land").expect("a file to try to upload");
    let (ok, text) = run(
        addr.port(),
        "NETLOGON",
        Some(USER),
        &format!(r#"put "{}" "evil.bat""#, source.display()),
    );
    assert!(!ok, "a write must fail, and the client said: {text}");
    let _ = std::fs::remove_file(&source);
    assert!(
        !scripts.path().join("evil.bat").exists(),
        "no file reached the directory"
    );

    task.abort();
}
