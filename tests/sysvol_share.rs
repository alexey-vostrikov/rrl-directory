//! The policy volume over real SMB, read and written by a real client.
//!
//! The unit tests in `sysvol::share` answer questions about the backend: does a path resolve, does
//! a write fail, does a listing carry the spelling the policy wrote. None of them says that a client
//! can reach any of it - the tree connect, the session, the SMB2 CREATE and QUERY_DIRECTORY calls
//! between a client and this backend are exactly where a backend that looks right stops working.
//!
//! So this drives `smbclient`, the one in Samba, against a listener on a port the kernel picks. It is
//! not a mock and not a second implementation: it is the client a fleet already has.
//!
//! # Both directions, because the share is `Authenticated Users`
//!
//! A download that works proves the backend serves bytes. It does not prove that an anonymous client
//! is refused, and a policy says which accounts may log on where - so the test connects twice: once
//! with no credentials, which must fail, and once as a user, which must work. A mode that admitted
//! anonymous would pass the first half of that alone.
//!
//! # When it does not run
//!
//! `smbclient` is a package, not a build dependency, and a machine without Samba should not fail
//! this repository's tests. Absent, the test says so and returns - and the run has to be read, not
//! counted: a skipped test is not a passing one, and this one exists because "it compiles" was
//! mistaken for "it serves" once already.

#![cfg(feature = "smb")]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rrl_directory::sysvol::profiles::{DEFAULT_DOMAIN_POLICY, Windows};
use rrl_directory::sysvol::{Machine, Policy, Registry, Rendered, Volume};

/// The domain under the share, which is where a controller keeps its policies.
const DOMAIN: &str = "ad.example.com";

/// An account the test server accepts, so that a client can log on: the share mode is about the
/// logon, and a logon is still needed.
const USER: &str = "alice";

/// Not a secret: this account exists for the length of one test, in a process nobody else reaches.
const PASSWORD: &str = "Pa55word!-for-one-test";

/// The policy the domain gets, with settings in both files a client fetches.
fn volume() -> Arc<dyn Volume> {
    let policy = Policy {
        guid: DEFAULT_DOMAIN_POLICY.to_string(),
        name: "Default Domain Policy".to_string(),
        version: 7,
        machine: Machine {
            registry: vec![Registry::dword(r"Software\Policies\Ad", "Enabled", 1)],
            rights: vec![(
                "SeInteractiveLogonRight".to_string(),
                vec!["*S-1-5-32-544".to_string()],
            )],
            startup: Vec::new(),
            system_access: Vec::new(),
        },
    };
    Arc::new(Rendered::new(vec![policy], Windows))
}

/// `smbclient`'s version, or `None` when Samba is not installed here.
fn smbclient() -> Option<String> {
    let output = Command::new("smbclient").arg("--version").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// One `smbclient` command against the share, as `user` or anonymously, with stdout and stderr
/// together.
///
/// The port goes in `-p`, not in the UNC: `smbclient` reads `//host:port/share` as a host name and
/// fails at `getaddrinfo`, which is a confusing way to learn this.
fn run(port: u16, user: Option<&str>, command: &str) -> (bool, String) {
    let mut invocation = Command::new("smbclient");
    invocation.arg("//127.0.0.1/SYSVOL").args([
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

// Multi-threaded on purpose: the client is a blocking process, and on the default current-thread
// runtime its `wait` holds the only thread the SMB accept loop could run on - which reads as a
// server that does not answer NEGOTIATE, twenty seconds of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_client_reads_a_policy_over_smb_and_an_anonymous_one_does_not() {
    let Some(version) = smbclient() else {
        eprintln!("skipping: smbclient is not installed, so nothing was proved about the share");
        return;
    };
    eprintln!("smbclient: {version}");

    let rendered = volume();
    let share = rrl_directory::sysvol::share::share(Arc::clone(&rendered), "SYSVOL", DOMAIN);
    let server = smb_server::SmbServer::builder()
        .listen((std::net::Ipv4Addr::LOCALHOST, 0).into())
        .netbios_name("DC1")
        .user(USER, PASSWORD)
        .share(share)
        // No listing of the server's other shares: this test asks about one share, and a listing
        // would be a second thing to keep true.
        .share_listing(false)
        .build()
        .expect("a server with one read-only share");
    let addr = server.bind().await.expect("a port the kernel picks");
    let task = tokio::spawn(server.serve());

    // Wait for the accept loop rather than for a duration: a fixed sleep is a test that fails on a
    // loaded machine and passes on an idle one, and the failure it produces names the client, not
    // the server. If the loop itself ended, its error is what the operator needs to see.
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

    // The refusal first, because it is the half a passing download says nothing about: a policy says
    // which accounts may log on where, and an anonymous client must get none of it.
    let (ok, text) = run(addr.port(), None, "ls");
    assert!(
        !ok,
        "an anonymous client must not reach the share, and it said: {text}"
    );
    assert!(
        text.contains("NT_STATUS_ACCESS_DENIED") || text.contains("NT_STATUS_LOGON_FAILURE"),
        "and the refusal names a status: {text}"
    );

    // The root: what a logged-on client enumerates before it knows where policies live.
    let (ok, text) = run(addr.port(), Some(USER), "ls");
    assert!(ok, "a listing of the share root: {text}");
    assert!(
        text.contains(DOMAIN),
        "the root listing names the domain folder, which is where a controller keeps policies: {text}"
    );

    // The version file, inside the policy folder, fetched by a path Windows writes.
    let (ok, text) = run(
        addr.port(),
        Some(USER),
        &format!(r#"cd "{DOMAIN}\Policies\{DEFAULT_DOMAIN_POLICY}"; ls"#),
    );
    assert!(ok, "the policy folder: {text}");
    assert!(
        text.contains("GPT.INI"),
        "the version file, with the spelling the policy wrote: {text}"
    );
    assert!(
        text.contains("Machine"),
        "and the folder the settings live in: {text}"
    );

    // The bytes: fetched, then compared with what the volume says they are. A listing that carries
    // the right names and a file that carries the wrong bytes would pass everything above.
    let destination = std::env::temp_dir().join("rrl-sysvol-gpt.ini");
    let _ = std::fs::remove_file(&destination);
    let (ok, text) = run(
        addr.port(),
        Some(USER),
        &format!(
            r#"get "{DOMAIN}\Policies\{DEFAULT_DOMAIN_POLICY}\GPT.INI" "{}""#,
            destination.display()
        ),
    );
    assert!(ok, "fetching GPT.INI: {text}");
    let fetched = std::fs::read(&destination).expect("the file the client wrote");
    let expected = rendered
        .read(DEFAULT_DOMAIN_POLICY, "GPT.INI")
        .expect("the same file from the volume");
    assert_eq!(
        fetched, expected,
        "the bytes a client got are the bytes the volume rendered"
    );
    let _ = std::fs::remove_file(&destination);

    // And the refusal: a client that tries to write gets an error, not a silent success. Read-only
    // is the one property of this share that a mistake would make invisible - a policy that can be
    // overwritten is a policy a member account can change for everyone.
    let source = std::env::temp_dir().join("rrl-sysvol-write.txt");
    std::fs::write(&source, b"should not land").expect("a file to try to upload");
    let (ok, text) = run(
        addr.port(),
        Some(USER),
        &format!(
            r#"put "{}" "{DOMAIN}\Policies\{DEFAULT_DOMAIN_POLICY}\evil.txt""#,
            source.display()
        ),
    );
    assert!(!ok, "a write must fail, and the client said: {text}");
    assert!(
        text.contains("ACCESS_DENIED") || text.contains("NT_STATUS"),
        "the refusal names a status: {text}"
    );
    let _ = std::fs::remove_file(&source);

    // The file is not there afterwards: a refusal that still stored the bytes would be worse than
    // one that did not.
    let (ok, text) = run(
        addr.port(),
        Some(USER),
        &format!(r#"cd "{DOMAIN}\Policies\{DEFAULT_DOMAIN_POLICY}"; ls evil.txt"#),
    );
    assert!(
        !ok || !text.contains("evil.txt"),
        "no file was created: {text}"
    );

    task.abort();
}
