//! The volume as an SMB share: a read-only tree built from [`Volume`] when the share is mounted.
//!
//! # Why a tree and not a call into the volume
//!
//! A client fetches a policy by walking it: `QUERY_DIRECTORY` on `Policies`, then on
//! `Policies\{GUID}`, then `CREATE` for each file. Every one of those is a separate request, and a
//! backend that recomputed the policy per request would render the same `registry.pol` a dozen times
//! per `gpupdate`. The tree is built once, at mount, from the volume - and rebuilt only when the
//! volume is rebuilt, which is the same contract the DNS listener has: one snapshot answers every
//! request until a new snapshot replaces it.
//!
//! # Why it cannot be written
//!
//! [`BackendCapabilities::is_read_only`] is set, and the protocol layer refuses every write-class
//! operation before this code sees it. The refusals below are therefore a second line and not the
//! first: a backend that answered `Ok` to a write the layer let through would be worse than one that
//! panics, because the client would believe it stored something. Nothing here is stored, so nothing
//! can be stored wrongly - a policy is rendered from the directory on every mount.
//!
//! # Why no files on disk
//!
//! Writing the rendered policies to a temporary directory and serving that with the local filesystem
//! backend would be less code, and it would put a second copy of every policy on disk - a copy that
//! nothing rebuilds when `versionNumber` changes. That divergence is exactly what the volume exists
//! to prevent, so the share reads the volume directly.

use std::collections::BTreeMap;
use std::sync::Arc;

use smb_server::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent,
    OpenOptions, Share, ShareBackend, SmbError, SmbPath, SmbResult,
};

use super::{Volume, policy_root};

/// One node of the tree: a directory or a file.
///
/// A directory carries no children of its own: the tree is flat, keyed by lowercased path, and a
/// listing walks the keys with the directory's prefix. That keeps one map instead of a nested
/// structure that has to be kept consistent - a policy that adds a file at `Machine\a\b\c.txt`
/// introduces three directories, and a nested tree would have to create each of them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// `name` is the spelling the volume rendered, not the key: a listing that answered `secedit`
    /// where the policy wrote `SecEdit` would be a share whose names do not match the paths inside
    /// `gPCMachineExtensionNames`.
    Directory {
        name: String,
    },
    File {
        name: String,
        bytes: Arc<Vec<u8>>,
    },
}

/// The rendered volume, as the share serves it.
#[derive(Debug)]
pub struct Mount {
    /// Keyed by lowercased path, backslash-separated, without a leading separator.
    nodes: BTreeMap<String, Node>,
    /// The domain the policies belong to, which is the first component under the share. Kept so a
    /// caller can say what it mounted, and so the root listing can name the folder a client walks
    /// into first.
    domain: String,
}

impl Mount {
    /// Builds the tree a share serves, from every policy the volume holds.
    ///
    /// A policy with no files contributes its own directory and nothing else: a policy that sets
    /// nothing still exists, and a client that cannot open its folder reports the policy as missing
    /// rather than as empty - which is the difference between "nothing is configured" and "the
    /// server does not have this policy".
    pub fn new(volume: &dyn Volume, domain: &str) -> Self {
        let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
        // The domain folder under the share, and `Policies` inside it: a client walks
        // `<domain>\Policies\{GUID}`, and the domain level is not optional - one `SYSVOL` serves the
        // whole forest.
        nodes.insert(
            normalise_key(domain),
            Node::Directory {
                name: domain.to_string(),
            },
        );

        for policy in volume.policies() {
            let root = policy_root(domain, &policy.guid);
            insert_directory(&mut nodes, &root);
            for file in volume.files(&policy.guid) {
                let path = format!("{root}\\{}", file.path);
                insert_file(&mut nodes, &path, file.bytes);
            }
        }
        Self {
            nodes,
            domain: domain.to_string(),
        }
    }

    /// The domain whose policies this mount renders, as it appears under the share.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Where `path` sits in the tree: a file, a directory, or nothing.
    ///
    /// `File` when the last component is a file, `Directory` when it is a directory or when it is
    /// only a prefix of something below it, `None` otherwise. The third case is the one SMB
    /// distinguishes with two statuses: an absent directory on the way is `PATH_NOT_FOUND`, an
    /// absent last component is `OBJECT_NAME_NOT_FOUND`.
    fn lookup(&self, path: &SmbPath) -> Lookup {
        let key = key(path);
        match self.nodes.get(&key) {
            Some(Node::File { name, bytes }) => Lookup::File {
                name: name.clone(),
                bytes: Arc::clone(bytes),
            },
            Some(Node::Directory { name }) => Lookup::Directory { name: name.clone() },
            // A name invented by a path but never inserted - a directory implied by something
            // below it. Its spelling comes from the client, which is all that is known about it.
            None if self.has_children(&key) => Lookup::Directory {
                name: path
                    .components()
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "SYSVOL".to_string()),
            },
            None => Lookup::Absent,
        }
    }

    /// Whether anything in the tree lives below `key`.
    fn has_children(&self, key: &str) -> bool {
        if key.is_empty() {
            return !self.nodes.is_empty();
        }
        let prefix = format!("{key}\\");
        // `range` from the prefix: the first key at or after it decides, because the map is sorted.
        self.nodes
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(candidate, _)| candidate.starts_with(&prefix))
    }

    /// One entry per child of `path`, named by its last component.
    fn children(&self, path: &SmbPath, pattern: Option<&str>) -> Vec<DirEntry> {
        let key = key(path);
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{key}\\")
        };

        let mut entries: Vec<DirEntry> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (candidate, _) in self.nodes.range(prefix.clone()..) {
            if !candidate.starts_with(&prefix) {
                break;
            }
            let rest = &candidate[prefix.len()..];
            // The key of the child this entry stands for: the whole candidate for a direct child,
            // and prefix plus the first component for something deeper.
            let child = match rest.split_once('\\') {
                Some((first, _)) => format!("{prefix}{first}"),
                None => candidate.clone(),
            };
            if !seen.insert(child.clone()) {
                continue;
            }
            // The name comes from the node, never from the key: the key is lowercased, and a
            // listing that answered `secedit` would be a folder whose name does not match the path
            // the policy wrote.
            let info = match self.nodes.get(&child) {
                Some(Node::File { name, bytes }) => file_info(name, bytes.len()),
                Some(Node::Directory { name }) => directory_info(name),
                // A name only a path knows - the fallback, and the client's own spelling.
                None => directory_info(rest.split('\\').next().unwrap_or(rest)),
            };
            // The pattern is what a client asked for - `*.pol` and the like - and it applies to the
            // name, not the path, as on a real share.
            if pattern.is_some_and(|pattern| !matches(pattern, &info.name)) {
                continue;
            }
            entries.push(DirEntry { info });
        }
        entries
    }
}

/// What a path names, once the tree has answered.
enum Lookup {
    File { name: String, bytes: Arc<Vec<u8>> },
    Directory { name: String },
    Absent,
}

/// Inserts a directory and every directory above it.
fn insert_directory(nodes: &mut BTreeMap<String, Node>, path: &str) {
    let mut current = String::new();
    for component in path.split('\\') {
        if component.is_empty() {
            continue;
        }
        if !current.is_empty() {
            current.push('\\');
        }
        current.push_str(component);
        nodes
            .entry(normalise_key(&current))
            .or_insert_with(|| Node::Directory {
                name: component.to_string(),
            });
    }
}

/// Inserts a file, and the directories on the way to it.
fn insert_file(nodes: &mut BTreeMap<String, Node>, path: &str, bytes: Vec<u8>) {
    let (directory, name) = match path.rsplit_once('\\') {
        Some((directory, name)) => (Some(directory), name),
        None => (None, path),
    };
    if let Some(directory) = directory {
        insert_directory(nodes, directory);
    }
    nodes.insert(
        normalise_key(path),
        Node::File {
            name: name.to_string(),
            bytes: Arc::new(bytes),
        },
    );
}

/// The map key of a path: lowercased, separators normalised, no leading separator.
fn normalise_key(path: &str) -> String {
    path.trim_start_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn key(path: &SmbPath) -> String {
    normalise_key(&path.components().join("\\"))
}

/// A stable id for a path, so that the same file reports the same `file_index` across opens.
///
/// A hash and not a counter: the tree is rebuilt on every mount, and a counter would hand a file a
/// different id after a reload, which is what `file_index` exists to prevent. Hash collisions would
/// make two files share a lock's identity - for policies, whose paths differ in a GUID, they are
/// not a practical concern, and the alternative (an interning table carried across reloads) is
/// state the server does not have.
fn file_index(key: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    // Zero means "no id" to the protocol layer, so it must not be a hash result.
    hasher.finish() | 1
}

fn file_info(name: &str, length: usize) -> FileInfo {
    let mut info = FileInfo::new(name);
    info.end_of_file = length as u64;
    info.allocation_size = length as u64;
    info.read_only = true;
    info
}

fn directory_info(name: &str) -> FileInfo {
    let mut info = FileInfo::new(name);
    info.is_directory = true;
    info.read_only = true;
    info
}

/// Whether `name` matches a client pattern, in the two wildcards SMB uses.
///
/// `*` for any run of characters, `?` for one, compared without case because the share is. Written
/// out rather than delegated to a crate: the pattern grammar is these two characters, and a
/// dependency for it would be more code to keep than the twenty lines it replaces.
fn matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let name: Vec<char> = name.to_ascii_lowercase().chars().collect();

    // `*` may match any run, so the matcher remembers the last `*` and the position it took,
    // instead of recursing: linear in the name, and no stack for a pattern like `*a*a*a`.
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, n));
                p += 1;
            }
            Some('?') => {
                p += 1;
                n += 1;
            }
            Some(&expected) if expected == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some((star_p, star_n)) => {
                    p = star_p + 1;
                    n = star_n + 1;
                    star = Some((star_p, star_n + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

/// The share a volume is served from.
///
/// Read-only. `gpupdate` runs in a session that already holds a ticket, and a policy says which
/// accounts may log on where, so it is not something to hand out before a logon.
///
/// # Which principals
///
/// `AuthenticatedReadOnly` - `S-1-5-11`, any principal that logged on, and nothing for an anonymous
/// session. That is the layer AD puts on the share. The second layer AD has is an NTFS ACL of
/// `Authenticated Users: Read` on the files; here the files are a rendering and there is no ACL
/// behind them, so this mode is the whole access decision rather than half of one. The difference
/// from a controller: no per-file rights, so no way to say "this policy is for domain admins".
pub fn share(volume: Arc<dyn Volume>, name: &str, domain: &str) -> Share {
    let mount = Mount::new(volume.as_ref(), domain);
    Share::new(name, mount)
        .authenticated_read_only()
        // No leases: a policy is written once per mount and read by clients that compare
        // `GPT.INI` before they fetch anything else. Leasing a file that cannot change only asks
        // the client to keep a copy of a snapshot the server would send again for free.
        .leases(false)
        // No change notifications for the same reason: nothing changes until the volume is
        // rebuilt, and a client that asked to be told would wait for an event that cannot come.
        .change_notify(false)
}

#[async_trait::async_trait]
impl ShareBackend for Mount {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        // The tree is a rendering, not storage: there is nothing to create. The protocol layer
        // refuses these before they arrive, because the capabilities say the share is read-only,
        // and this is the second line - a create that reached a backend and succeeded would tell
        // the client it had stored a policy.
        if matches!(
            opts.intent,
            OpenIntent::Create | OpenIntent::OverwriteOrCreate | OpenIntent::Truncate
        ) {
            return Err(SmbError::AccessDenied);
        }

        match self.lookup(path) {
            Lookup::File { name, bytes } => {
                if opts.directory {
                    return Err(SmbError::NotADirectory);
                }
                Ok((Box::new(FileHandle::new(name, bytes)), OpenAction::Opened))
            }
            Lookup::Directory { name } => {
                if opts.non_directory {
                    return Err(SmbError::IsDirectory);
                }
                Ok((
                    Box::new(DirHandle {
                        name,
                        entries: self.children(path, None),
                    }),
                    OpenAction::Opened,
                ))
            }
            Lookup::Absent => {
                // A directory on the way that does not exist is `PATH_NOT_FOUND`; only the last
                // component missing is `OBJECT_NAME_NOT_FOUND`. A client distinguishes them: the
                // first means the policy folder is wrong, the second that this policy has no such
                // file.
                let mut parent = path.components().to_vec();
                parent.pop();
                if parent.is_empty() || self.has_children(&parents_key(&parent)) {
                    Err(SmbError::NotFound)
                } else {
                    Err(SmbError::PathNotFound)
                }
            }
        }
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn rename(&self, _from: &SmbPath, _to: &SmbPath, _replace: bool) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = BackendCapabilities::default();
        capabilities.is_read_only = true;
        // The tree is keyed by lowercased path, so it cannot tell `GPT.INI` from `gpt.ini` -
        // which is what the clients expect, and what a case-sensitivity claim would deny.
        capabilities.case_sensitive = false;
        capabilities
    }
}

fn parents_key(components: &[String]) -> String {
    normalise_key(&components.join("\\"))
}

/// An open file: the bytes the volume rendered, and the name the client asked by.
struct FileHandle {
    name: String,
    bytes: Arc<Vec<u8>>,
}

impl FileHandle {
    fn new(name: String, bytes: Arc<Vec<u8>>) -> Self {
        Self { name, bytes }
    }
}

#[async_trait::async_trait]
impl Handle for FileHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<smb_server::Bytes> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= self.bytes.len() {
            // A read at or past the end is empty, not an error: the client may ask for more than
            // the file has, and SMB answers with what it got.
            return Ok(smb_server::Bytes::new());
        }
        let end = start.saturating_add(len as usize).min(self.bytes.len());
        Ok(smb_server::Bytes::copy_from_slice(&self.bytes[start..end]))
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::AccessDenied)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let mut info = file_info(&self.name, self.bytes.len());
        info.file_index = file_index(&self.name);
        Ok(info)
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn set_attributes(&self, _attributes: u32) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Err(SmbError::NotADirectory)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

/// An open directory: the listing taken when it was opened, and the name.
///
/// The entries are computed once, at `open`, because the tree cannot change while the mount lasts.
/// Nothing is invalidated, so a directory handle held across a session answers the same bytes it
/// would have answered at the start - which for a rendered volume is the truth.
struct DirHandle {
    name: String,
    entries: Vec<DirEntry>,
}

#[async_trait::async_trait]
impl Handle for DirHandle {
    async fn read(&self, _offset: u64, _len: u32) -> SmbResult<smb_server::Bytes> {
        Err(SmbError::IsDirectory)
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::AccessDenied)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let mut info = directory_info(&self.name);
        info.file_index = file_index(&self.name);
        Ok(info)
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn set_attributes(&self, _attributes: u32) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(match pattern {
            Some(pattern) => self
                .entries
                .iter()
                .filter(|entry| matches(pattern, &entry.info.name))
                .cloned()
                .collect(),
            None => self.entries.clone(),
        })
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysvol::profiles::{DEFAULT_DOMAIN_POLICY, Windows};
    use crate::sysvol::{Machine, Policy, Registry, Rendered};

    /// The domain the policies belong to: the first component under the share.
    const DOMAIN: &str = "ad.example.com";

    /// The policy the domain gets, with one setting in each place that produces a nested path.
    ///
    /// A policy with no settings would exercise only `GPT.INI`, and the interesting part of a share
    /// is the directories a client never sees an entry for: `Machine\Microsoft\Windows NT\SecEdit`
    /// exists only because `GptTmpl.inf` lives below it.
    fn volume() -> Arc<dyn Volume> {
        let policy = Policy {
            guid: DEFAULT_DOMAIN_POLICY.to_string(),
            name: "Default Domain Policy".to_string(),
            version: 3,
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

    fn mount() -> Mount {
        Mount::new(volume().as_ref(), DOMAIN)
    }

    fn path(text: &str) -> SmbPath {
        let units: Vec<u16> = text.encode_utf16().collect();
        SmbPath::from_utf16(&units).expect("a path a client can send")
    }

    async fn read_all(mount: &Mount, text: &str) -> SmbResult<Vec<u8>> {
        let (handle, _) = mount.open(&path(text), OpenOptions::default()).await?;
        let bytes = handle.read(0, u32::MAX).await?;
        Ok(bytes.to_vec())
    }

    /// The property a share exists for: the bytes a client gets are the bytes the volume rendered.
    #[tokio::test]
    async fn the_version_file_comes_back_through_the_share() {
        let mount = mount();
        let served = read_all(
            &mount,
            &format!("{DOMAIN}\\Policies\\{DEFAULT_DOMAIN_POLICY}\\GPT.INI"),
        )
        .await
        .expect("the file the volume publishes");
        let rendered = volume()
            .read(DEFAULT_DOMAIN_POLICY, "GPT.INI")
            .expect("the same file from the volume");
        assert_eq!(served, rendered);
        // `GPT.INI` is UTF-16LE, so the version is compared after decoding it the way a client
        // does - and not by looking for ASCII in a file that has none.
        let text = crate::sysvol::inf::decode(&served).expect("a UTF-16 file with a BOM");
        assert!(
            text.contains("Version=3"),
            "the version a client compares, taken from the entry: {text:?}"
        );
    }

    /// Windows asks with the case it stored, and SSSD asks with another; one file answers both.
    #[tokio::test]
    async fn a_client_may_ask_in_any_case() {
        let mount = mount();
        // Upper-cased domain and lower-cased GUID: the two halves asked differently from the way
        // they were rendered, and both have to find the same file.
        let lower = format!(
            "{}\\policies\\{}\\gpt.ini",
            DOMAIN.to_uppercase(),
            DEFAULT_DOMAIN_POLICY.to_lowercase()
        );
        assert!(
            read_all(&mount, &lower).await.is_ok(),
            "a path the share lowercases must still open"
        );
    }

    /// The directory nobody creates explicitly: three components, one file.
    #[tokio::test]
    async fn a_directory_that_holds_only_deeper_names_is_still_a_directory() {
        let mount = mount();
        let (handle, _) = mount
            .open(
                &path(&format!(
                    "{DOMAIN}\\Policies\\{DEFAULT_DOMAIN_POLICY}\\Machine\\Microsoft\\Windows NT"
                )),
                OpenOptions::default(),
            )
            .await
            .unwrap_or_else(|err| panic!("a directory on the way to GptTmpl.inf: {err:?}"));

        let info = handle.stat().await.expect("a directory stats");
        assert!(info.is_directory, "not a file");

        let entries = handle.list_dir(None).await.expect("a listing");
        let names: Vec<&str> = entries
            .iter()
            .map(|entry| entry.info.name.as_str())
            .collect();
        assert_eq!(names, vec!["SecEdit"], "the only child: {names:?}");
    }

    /// A missing file inside a policy and a missing policy are different answers, because a client
    /// acts on the difference: the first means "this policy sets nothing here", the second "there is
    /// no such policy".
    #[tokio::test]
    async fn a_missing_file_and_a_missing_policy_get_different_answers() {
        let mount = mount();

        let missing_file = mount
            .open(
                &path(&format!(
                    "{DOMAIN}\\Policies\\{DEFAULT_DOMAIN_POLICY}\\Machine\\startup.cmd"
                )),
                OpenOptions::default(),
            )
            .await;
        assert!(
            matches!(missing_file, Err(SmbError::NotFound)),
            "a file the policy does not publish is OBJECT_NAME_NOT_FOUND"
        );

        let missing_policy = mount
            .open(
                &path("{DOMAIN}\\Policies\\{00000000-0000-0000-0000-000000000000}\\GPT.INI"),
                OpenOptions::default(),
            )
            .await;
        assert!(
            matches!(missing_policy, Err(SmbError::PathNotFound)),
            "a policy folder that does not exist is PATH_NOT_FOUND"
        );
    }

    /// Nothing can be written, and each refusal names what the client tried to do.
    #[tokio::test]
    async fn nothing_can_be_written() {
        let mount = mount();
        let file = path(&format!(
            "{DOMAIN}\\Policies\\{DEFAULT_DOMAIN_POLICY}\\GPT.INI"
        ));

        let create = mount
            .open(
                &file,
                OpenOptions {
                    intent: OpenIntent::OverwriteOrCreate,
                    write: true,
                    ..OpenOptions::default()
                },
            )
            .await;
        assert!(
            matches!(create, Err(SmbError::AccessDenied)),
            "an overwrite of a policy file is refused"
        );

        assert!(matches!(
            mount.unlink(&file).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            mount.rename(&file, &file, false).await,
            Err(SmbError::AccessDenied)
        ));

        // And the handle itself refuses, in case the protocol layer ever lets one through.
        let (handle, _) = mount
            .open(&file, OpenOptions::default())
            .await
            .unwrap_or_else(|err| panic!("a policy file a client reads: {err:?}"));
        assert!(matches!(
            handle.write(0, b"x").await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.truncate(0).await,
            Err(SmbError::AccessDenied)
        ));
    }

    #[test]
    fn the_share_is_read_only_and_case_insensitive() {
        let capabilities = mount().capabilities();
        assert!(
            capabilities.is_read_only,
            "a policy is rendered, not stored"
        );
        assert!(
            !capabilities.case_sensitive,
            "SMB clients ask in either case, and the tree is keyed that way"
        );
    }

    /// `*.ini` narrows a listing the way a client expects, and the pattern is applied to the name.
    #[tokio::test]
    async fn a_glob_narrows_a_listing() {
        let mount = mount();
        let (handle, _) = mount
            .open(
                &path(&format!("{DOMAIN}\\Policies\\{DEFAULT_DOMAIN_POLICY}")),
                OpenOptions::default(),
            )
            .await
            .unwrap_or_else(|err| panic!("the policy folder: {err:?}"));

        let all = handle.list_dir(None).await.expect("everything");
        let names: Vec<&str> = all.iter().map(|entry| entry.info.name.as_str()).collect();
        assert!(names.contains(&"GPT.INI"), "the version file: {names:?}");
        assert!(names.contains(&"Machine"), "the settings: {names:?}");

        let ini = handle.list_dir(Some("*.ini")).await.expect("a pattern");
        let names: Vec<&str> = ini.iter().map(|entry| entry.info.name.as_str()).collect();
        assert_eq!(names, vec!["GPT.INI"], "only the file the pattern names");
    }

    #[test]
    fn a_pattern_is_the_two_wildcards_and_nothing_else() {
        assert!(matches("*", "anything"));
        assert!(matches("*.pol", "Registry.pol"), "without case");
        assert!(matches("?pt.ini", "gpt.ini"), "one character");
        assert!(matches("a*b*c", "axxbyyc"), "a star matches a run");
        // The case a naive matcher gets wrong: the first star must give back characters it took,
        // and the last one has to end the name. Both directions, because only the pair says the
        // backtracking works and does not match everything.
        assert!(
            matches("*a*a*a", "aaabaa"),
            "backtracks, without a recursion for it"
        );
        assert!(
            !matches("*a*a*a", "aaaaaaaaab"),
            "and still requires the name to end where the pattern does"
        );
        assert!(!matches("*.pol", "gpt.ini"));
        assert!(
            !matches("gpt.ini", "GPT.INI.bak"),
            "a full name, not a prefix"
        );
        assert!(
            !matches("?pt.ini", "pt.ini"),
            "`?` is one character, not none"
        );
    }
}
