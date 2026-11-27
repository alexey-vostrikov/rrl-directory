//! SMB in this process: port 445, and the `IPC$` share a join talks to.
//!
//! A Samba member's first step in `net ads join` is not LDAP and not Kerberos: it is an SMB
//! connection to `\\DC\IPC$`, and everything after it - opening the `lsarpc` pipe, asking LSA who the
//! domain is - travels through that connection. Measured rather than assumed: the stand fails with
//! `transport-connection attempt was refused` from `libnet_join_connect_dc_ipc`, before any RPC is
//! spoken (`source3/libnet/libnet_join.c`).
//!
//! # What this module is
//!
//! The wiring, not the protocol. `smb-server` carries SMB2/3, the tree connect, the named pipes of
//! `IPC$` and DCE/RPC over them; this module decides the address, the name, the credentials and how
//! to stop. The same split as the KDC: an engine with no sockets, and a daemon that owns them.
//!
//! # File shares: two, and only when asked for
//!
//! `IPC$` is what a join needs, and it is the only share this module mounts unless a deployment
//! says otherwise. Two settings add a file share:
//!
//!   * `smb.sysvol_share` mounts `SYSVOL`: the directory's policies rendered as the files a member
//!     fetches, from the same `groupPolicyContainer` objects the LDAP half serves, read-only, from a
//!     tree built at mount. A snapshot, because a policy is compared by version before it is applied
//!     and one rebuild point is the honest shape.
//!   * `smb.netlogon_dir` mounts `NETLOGON`: the logon scripts, from a directory on disk, read live.
//!     In AD both names are the same folder - `scripts` inside `SYSVOL` - but a logon script is a
//!     file an administrator edits, and a snapshot would report a script as missing until the next
//!     rebuild.
//!
//! Both are off by default, and the reason is not caution for its own sake: a share is a second path
//! into a process whose access rules are about tickets, so it is mounted when a deployment asks for
//! it. Both run in `AuthenticatedReadOnly` - an anonymous session is refused and every logged-on
//! account may read, which is what these folders are in AD and what a member needs with the ticket it
//! already holds.

pub mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;

/// What the `smb:` section says.
///
/// Off by default, like `kerberos:`: a server that answers on 445 is a server claiming to be a
/// domain controller, and one that answers and then cannot complete a join sends a machine to a dead
/// end with a message about a transport.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmbConfig {
    /// Whether to serve SMB at all.
    pub enabled: bool,
    /// The port.
    ///
    /// 445 by default, the only port a client tries. A different value exists for one honest
    /// reason: only root may bind below 1024, and a test or a developer without that right still has
    /// to be able to check the handshake end to end.
    pub port: Option<u16>,
    /// The NetBIOS name this server answers to, `SAMBA`.
    ///
    /// Defaults to the host name of the DNS name the CLDAP section advertises, upper-cased, so that
    /// a client which found this server one way recognises it by the other. Two names for one server
    /// is how a machine ends up joined to a controller it cannot reach.
    pub netbios_name: Option<String>,
    /// Accounts SMB accepts a password for.
    ///
    /// NTLM only, and deliberately narrow: this is for the one path a Kerberos realm cannot carry -
    /// a client that joins with an account's password rather than a ticket. A deployment that has a
    /// keytab needs none of these, and one that has only these has no domain logon.
    ///
    /// The password is named by an environment variable rather than written here, for the same
    /// reason the bootstrap section does: a configuration file is read by whatever runs the server,
    /// and a password in it is a password in `ps` for anybody who can read one.
    #[serde(default)]
    pub users: Vec<SmbUser>,
    /// The DNS name of the domain, `ad.example.com`.
    ///
    /// Derived from the naming context when absent, by the same rule `KerberosConfig` uses, so that
    /// the realm, the CLDAP answer and this cannot disagree.
    pub dns_domain: Option<String>,
    /// The domain's NetBIOS name, `AD`. Derived from `dns_domain` when absent.
    #[serde(default)]
    pub domain_netbios: Option<String>,
    /// The `ncacn_ip_tcp` port `drsuapi` is served on, the one the endpoint mapper names.
    ///
    /// A Windows join asks the endpoint mapper (port 135) where `drsuapi` lives and is told a **TCP
    /// port**; it then opens that port and binds the replication interface there. A server that
    /// offers no such port is a controller the join cannot reach, whatever else answers correctly -
    /// measured: without it `NetpGetComputerObjectDn` fails with `RPC_S_SERVER_UNAVAILABLE`.
    ///
    /// Off unless set, because a port nobody asked for is a listener nobody wanted. The port is
    /// stated here rather than picked at start for the same reason a real controller states nothing
    /// in a file: it is published, and a client reads it from the mapper instead of guessing.
    pub drsuapi_port: Option<u16>,
    /// The `ncacn_ip_tcp` port `netlogon` is served on.
    ///
    /// A port of its own, beside the `drsuapi` one, because that is where a client looks for it: a
    /// controller that names the secure channel on the port another interface already answers on
    /// leaves the tower one the client does not use, and the channel it then builds over the named
    /// pipe is one it refuses afterwards. Measured against Samba, which separates the two
    /// (`49153` for `netlogon`, `49152` for `drsuapi`).
    ///
    /// Defaults to `drsuapi_port + 1` when that is free and the stated port when it is not - the
    /// configuration may state either, and the pair is what the mapper publishes.
    pub netlogon_port: Option<u16>,
    /// The `ncacn_ip_tcp` port the endpoint mapper listens on, 135 unless stated.
    ///
    /// The mapper is how a client learns the port above: it asks here, with the interface id it
    /// wants, and is answered with a tower naming that port. Without it the client's `DsBind` fails
    /// with `RPC_S_SERVER_UNAVAILABLE` and a join stops - so it is started whenever `drsuapi_port`
    /// is set, and a port that cannot be taken is a startup error naming it rather than a join that
    /// fails later for a reason nobody can see from the client side.
    #[serde(default)]
    pub epm_port: Option<u16>,
    /// A keytab for Kerberos in SESSION_SETUP.
    ///
    /// Without it the server accepts NTLM only, which a Samba member can use with an administrator's
    /// password and a Windows member will refuse. Read at start and never re-read: a keytab that
    /// changes under a running server is a keytab an operator meant to restart for.
    pub keytab: Option<PathBuf>,
    /// Serve the secure channel of a client that offers no AES, which means DES.
    ///
    /// Off by default. The credential on that channel is two DES passes over a 56-bit key, and
    /// every current member offers `NETLOGON_NEG_SUPPORTS_AES` instead; a deployment that has to
    /// accept an old one turns this on knowing what it is. With it off, such a client is refused
    /// with a line naming this setting rather than with "the password is wrong".
    #[serde(default)]
    pub netlogon_des: bool,
    /// Mount `SYSVOL`: the directory's policies rendered as the files a member fetches.
    ///
    /// Off by default, and the reason is not caution for its own sake: a share is a second path
    /// into a process whose access rules are about tickets, so it is mounted when a deployment asks
    /// for it rather than always. When mounted it is `AuthenticatedReadOnly` - anonymous sessions
    /// are refused, every logged-on account may read, and nothing may be written - so a member
    /// fetches its policies with the ticket it already has and an unauthenticated client learns
    /// nothing. That mode did not exist in `smb-server` when this setting was written; it does now,
    /// and the setting no longer widens access beyond the domain.
    #[serde(default)]
    pub sysvol_share: bool,
    /// Mount `NETLOGON` from this directory: the logon scripts a member runs, as files.
    ///
    /// In AD `NETLOGON` is the `scripts` folder *inside* `SYSVOL`, and the scripts there are files,
    /// not directory entries - which is why this cannot be rendered from the policies the way
    /// `SYSVOL` is. The contents come from a directory instead, and that is the whole reason the key
    /// exists: a logon script is something an administrator edits in an editor and drops in, and a
    /// directory is how that keeps working.
    ///
    /// Read live from disk, deliberately, where `SYSVOL` is a snapshot: a policy governs a machine
    /// and is compared by version before it is applied, so a snapshot with one rebuild point is the
    /// honest shape. A logon script is fetched by name at logon with nothing to compare, so a stale
    /// listing reads as "the file is not there" seconds after it was written.
    ///
    /// A missing directory is refused at start rather than mounted empty: a share a client walks
    /// into and finds nothing is a logon that silently runs no scripts.
    #[serde(default)]
    pub netlogon_dir: Option<PathBuf>,
}

/// One account SMB accepts a password for.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmbUser {
    /// The account name, without a domain prefix.
    pub name: String,
    /// The environment variable holding the password.
    pub password_env: String,
}

/// The port the endpoint mapper listens on unless the configuration states another.
///
/// 135 is the port every client asks: a mapper somewhere else is one nothing looks for.
pub const DEFAULT_EPM_PORT: u16 = 135;

/// The resolved form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to listen.
    pub bind: SocketAddr,
    /// The name this server answers to.
    pub netbios_name: String,
    /// Where the keytab is, if there is one.
    pub keytab: Option<PathBuf>,
    /// The accounts resolved to their passwords.
    pub users: Vec<(String, String)>,
    /// Where `drsuapi` is served over `ncacn_ip_tcp`, when it is served at all.
    pub drsuapi_tcp: Option<SocketAddr>,
    /// Where the endpoint mapper is served, when `drsuapi` is.
    ///
    /// Always set together with `drsuapi_tcp`: an endpoint a client cannot find is an endpoint that
    /// does not exist, which is exactly the fault this pair was written for.
    pub epm_tcp: Option<SocketAddr>,
    /// The DNS name of the domain, `ad.example.com`.
    ///
    /// Answered by `lsarpc` when a member asks what domain it has reached. A client compares this
    /// against the realm it was told, and a wrong name sends it looking for another domain - so it
    /// comes from the same place CLDAP takes its answer from, not from a second derivation.
    pub dns_domain: Option<String>,
    /// The domain's SID in the octets a directory stores, when this server issues one.
    ///
    /// `lsarpc` reports it with the domain's DNS information, and a member's join stores it as the
    /// domain the machine belongs to. Filled by the daemon from the `sid::domain::Issuer` rather
    /// than from the configuration: a SID written into a file is a SID that can disagree with the
    /// one already on the accounts.
    pub domain_sid: Option<Vec<u8>>,
    /// The domain's NetBIOS name, `AD` for `AD.EXAMPLE.COM`.
    ///
    /// A member compares it against its configured workgroup before joining, so it is the domain's
    /// name and not this server's. Derived from the realm when the configuration does not state
    /// one, by AD's own rule: the realm's first label, upper case.
    pub domain_netbios: Option<String>,
    /// Serve the secure channel of a client that offers no AES.
    pub netlogon_des: bool,
    /// Mount `SYSVOL`, rendering the directory's policies into the files a member fetches.
    pub sysvol_share: bool,
    /// Where the `NETLOGON` scripts are on disk, when the share is mounted.
    ///
    /// The daemon checks the directory here rather than in [`SmbConfig`]: resolution runs before the
    /// daemon has a place to report a refusal, and a settings object that carries a path the mount
    /// cannot open is a share that fails at the first client instead of at start.
    pub netlogon_dir: Option<PathBuf>,
    /// The port the `netlogon` endpoint answers on, beside `drsuapi_tcp`.
    pub netlogon_tcp: Option<SocketAddr>,
    /// The address a client is told to reach this controller at, when one is configured.
    ///
    /// `netr_DsRGetDCNameEx2` answers with an address, and a controller that names its bind address
    /// names one only the host itself can reach. The value comes from the daemon, which knows the
    /// address the DNS zone publishes - the same question, answered once.
    pub dc_address: Option<std::net::Ipv4Addr>,
}

impl Settings {
    /// Resolves the section against the address the LDAP listener took.
    ///
    /// A missing `netbios_name` is refused rather than invented here: the name has to agree with
    /// what CLDAP advertises, and that is a decision the daemon makes once, in one place.
    pub fn resolve(
        config: &SmbConfig,
        bind_ip: std::net::IpAddr,
        netbios_name: Option<&str>,
    ) -> Result<Settings, String> {
        let port = config.port.unwrap_or(445);
        let netbios_name = match (&config.netbios_name, netbios_name) {
            (Some(name), _) => name.clone(),
            (None, Some(name)) => name.to_string(),
            (None, None) => {
                return Err(
                    "smb.netbios_name is not set and none can be derived: say `smb.netbios_name`"
                        .to_string(),
                );
            }
        };
        if netbios_name.is_empty() {
            return Err("smb.netbios_name is empty".to_string());
        }
        // A NetBIOS name is at most 15 octets (RFC 1001 §14.1), and a longer one is truncated by
        // every client that reads it - two servers whose names truncate to the same thing are two
        // servers a client cannot tell apart.
        if netbios_name.len() > 15 {
            return Err(format!(
                "smb.netbios_name '{netbios_name}' is {} octets, a NetBIOS name holds 15",
                netbios_name.len()
            ));
        }

        if let Some(keytab) = &config.keytab
            && !keytab.exists()
        {
            // Fail here rather than accept a bind that will refuse every Kerberos session: the
            // failure then names the file at start, once, instead of reading as a client problem.
            return Err(format!("smb.keytab '{}' does not exist", keytab.display()));
        }

        // Resolved here rather than at use: a password that is missing is a startup failure with
        // the variable's name in it, not a session setup that fails later for reasons the operator
        // has to guess at.
        let mut users = Vec::with_capacity(config.users.len());
        for user in &config.users {
            if user.name.is_empty() {
                return Err("smb.users: an account with an empty name".to_string());
            }
            let password = std::env::var(&user.password_env).map_err(|_| {
                format!(
                    "smb.users: '{}' names the password variable '{}', which is not set",
                    user.name, user.password_env
                )
            })?;
            if password.is_empty() {
                return Err(format!(
                    "smb.users: '{}' has an empty password in '{}'",
                    user.name, user.password_env
                ));
            }
            users.push((user.name.clone(), password));
        }

        // A port of zero would ask the operating system to pick one that no client can be told
        // about: the number here *is* the answer a client gets, and it is stated rather than chosen.
        let drsuapi_tcp = match config.drsuapi_port {
            None => None,
            Some(0) => return Err("smb.drsuapi_port is 0, which names no port".to_string()),
            Some(port) => Some(SocketAddr::new(bind_ip, port)),
        };
        // `netlogon` beside `drsuapi`, never on top of it: a client that finds two interfaces on one
        // port uses neither over TCP and falls back to the named pipe. Stated, or one above the
        // `drsuapi` port - a number the client is told, not one it guesses.
        let netlogon_tcp = match (drsuapi_tcp, config.netlogon_port) {
            (None, _) => None,
            (Some(_), Some(0)) => {
                return Err("smb.netlogon_port is 0, which names no port".to_string());
            }
            (Some(drsuapi), Some(port)) if drsuapi.port() == port => {
                return Err(format!(
                    "smb.netlogon_port is {port}, the port drsuapi answers on: the secure channel \
                     needs a port of its own"
                ));
            }
            (Some(drsuapi), Some(port)) => Some(SocketAddr::new(drsuapi.ip(), port)),
            (Some(drsuapi), None) => Some(SocketAddr::new(drsuapi.ip(), drsuapi.port() + 1)),
        };

        // The mapper goes with the interface it maps: one without the other is a controller whose
        // `DsBind` answers `RPC_S_SERVER_UNAVAILABLE` to a client that found the port by guessing.
        let epm_tcp = drsuapi_tcp.map(|_| {
            SocketAddr::new(
                bind_ip,
                config.epm_port.unwrap_or(crate::smb::DEFAULT_EPM_PORT),
            )
        });

        Ok(Settings {
            bind: SocketAddr::new(bind_ip, port),
            // Filled by the daemon, which is where the published address is known.
            dc_address: None,
            drsuapi_tcp,
            netlogon_tcp,
            epm_tcp,
            netbios_name,
            keytab: config.keytab.clone(),
            users,
            dns_domain: config.dns_domain.clone(),
            domain_sid: None,
            // The domain's NetBIOS name by AD's own rule: the DNS domain's first label, upper
            // case. Taken here rather than at the call site because the DNS name is resolved here,
            // and two places computing one name is two answers a member could be sent to.
            domain_netbios: config.domain_netbios.clone().or_else(|| {
                config
                    .dns_domain
                    .as_deref()
                    .and_then(|domain| domain.split('.').next())
                    .map(|label| label.to_ascii_uppercase())
            }),
            netlogon_des: config.netlogon_des,
            sysvol_share: config.sysvol_share,
            netlogon_dir: config.netlogon_dir.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    fn config() -> SmbConfig {
        SmbConfig {
            enabled: true,
            ..SmbConfig::default()
        }
    }

    #[test]
    fn a_drsuapi_port_is_carried_as_an_address_on_the_same_interface() {
        let settings = Settings::resolve(
            &SmbConfig {
                drsuapi_port: Some(49_152),
                ..config()
            },
            Ipv4Addr::LOCALHOST.into(),
            Some("SAMBA"),
        )
        .expect("resolves");
        assert_eq!(
            settings.drsuapi_tcp,
            Some("127.0.0.1:49152".parse().expect("a literal address"))
        );
    }

    #[test]
    fn no_drsuapi_port_means_no_listener() {
        let settings =
            Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.drsuapi_tcp, None);
    }

    #[test]
    fn a_drsuapi_port_of_zero_is_a_startup_error() {
        // The mapper is not implemented, so the number in the configuration *is* what a client is
        // told; zero would ask the operating system for one nobody can be told about.
        let err = Settings::resolve(
            &SmbConfig {
                drsuapi_port: Some(0),
                ..config()
            },
            Ipv4Addr::LOCALHOST.into(),
            Some("SAMBA"),
        )
        .expect_err("refuses");
        assert!(err.contains("drsuapi_port"), "{err}");
    }

    #[test]
    fn the_section_resolves_to_a_port_and_a_name() {
        let settings =
            Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.bind.port(), 445);
        assert_eq!(settings.netbios_name, "SAMBA");
    }

    #[test]
    fn a_netlogon_directory_survives_resolution() {
        // The path is carried rather than checked here: resolution runs before the daemon can report
        // a refusal, so the check that the directory exists and lists something happens where a
        // message reaches the operator. A `drop` of this field in `resolve` would be silent - the
        // share simply would not mount - so the field is asserted on.
        let with_dir = SmbConfig {
            netlogon_dir: Some(PathBuf::from("/srv/netlogon")),
            ..config()
        };
        let settings =
            Settings::resolve(&with_dir, Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.netlogon_dir, Some(PathBuf::from("/srv/netlogon")));

        // And absent stays absent: a deployment that mounts no scripts must not get a share at a
        // default path nobody wrote down.
        let settings =
            Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.netlogon_dir, None);
    }

    #[test]
    fn a_name_from_the_configuration_wins_over_the_derived_one() {
        // The configuration is the operator's decision; the derived name is a convenience for the
        // case they did not state one. A server whose two names disagree is a server a client
        // reaches by one and refuses by the other.
        let stated = SmbConfig {
            netbios_name: Some("DC1".to_string()),
            ..config()
        };
        let settings =
            Settings::resolve(&stated, Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(settings.netbios_name, "DC1");
    }

    #[test]
    fn a_name_nobody_stated_is_refused_rather_than_invented() {
        // Inventing one would produce a server that answers to a name CLDAP does not advertise, and
        // the client would find it by one and fail to reach it by the other.
        let error = Settings::resolve(&config(), Ipv4Addr::LOCALHOST.into(), None)
            .expect_err("a name is required");
        assert!(error.contains("netbios_name"), "{error}");
    }

    #[test]
    fn a_name_a_netbios_client_cannot_carry_is_refused() {
        let long = SmbConfig {
            netbios_name: Some("A-VERY-LONG-NETBIOS-NAME".to_string()),
            ..config()
        };
        let error = Settings::resolve(&long, Ipv4Addr::LOCALHOST.into(), None)
            .expect_err("15 octets at most");
        assert!(error.contains("15"), "{error}");
    }

    #[test]
    fn a_password_that_is_not_in_the_environment_stops_the_start() {
        // Named by a variable rather than written in the file, so this is where a missing one is
        // caught: a session setup failing later would say nothing about which variable to set.
        let configured = SmbConfig {
            users: vec![SmbUser {
                name: "administrator".to_string(),
                password_env: "RR_LDAP_TEST_MISSING_PASSWORD_VARIABLE".to_string(),
            }],
            ..config()
        };
        let error = Settings::resolve(&configured, Ipv4Addr::LOCALHOST.into(), Some("SAMBA"))
            .expect_err("the variable is not set");
        assert!(
            error.contains("RR_LDAP_TEST_MISSING_PASSWORD_VARIABLE"),
            "{error}"
        );
    }

    #[test]
    fn an_account_resolves_to_its_password() {
        // The one path a realm cannot carry: a client that joins with a password rather than a
        // ticket, which is what NTLM needs.
        //
        // `PATH` rather than a variable of its own: this crate forbids `unsafe`, so a test cannot
        // set one, and what is being checked is the reading, not the value.
        let expected = std::env::var("PATH").expect("PATH is set for any process");
        let configured = SmbConfig {
            users: vec![SmbUser {
                name: "administrator".to_string(),
                password_env: "PATH".to_string(),
            }],
            ..config()
        };

        let settings =
            Settings::resolve(&configured, Ipv4Addr::LOCALHOST.into(), Some("SAMBA")).expect("ok");
        assert_eq!(
            settings.users,
            vec![("administrator".to_string(), expected)]
        );
    }

    #[test]
    fn a_keytab_that_is_not_there_stops_the_start() {
        // Accepted silently, every Kerberos session would be refused later, and the refusal would
        // read as a client problem rather than as a missing file.
        let missing = SmbConfig {
            keytab: Some(PathBuf::from("/nonexistent/service.keytab")),
            ..config()
        };
        let error = Settings::resolve(&missing, Ipv4Addr::LOCALHOST.into(), Some("SAMBA"))
            .expect_err("the file does not exist");
        assert!(error.contains("does not exist"), "{error}");
    }
}
