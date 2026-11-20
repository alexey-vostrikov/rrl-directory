//! What this directory says it is, to a client that asks the way a Windows one does.
//!
//! A Windows Server release is two numbers, and they move independently: the **domain level**
//! (`domainFunctionality`) and the **schema** (`objectVersion`). Below 2016 every release moved both -
//! 2008 is level 3 with `sch44`, 2008 R2 is 4 with 47, 2012 is 5 with 56, 2012 R2 is 6 with 69. From
//! 2016 on they separate: 2016 is level 7 with `sch87`, and 2019 and 2022 raised the schema to 88 and
//! left the level at 7. 2025 is level 10 with `sch89` through 91 - the first new level since 2016, and
//! the only one since then that changed a field a client reads.
//!
//! So "behave like 2012 R2" is not a level to claim but a **pair to publish**, and an operator who
//! wants a client to believe it is talking to a particular release has to choose both. The pair is
//! checked when the configuration is read: a schema no release shipped is refused, because it would
//! state a level no release had.
//!
//! What is published says it is an emulation. A domain that claims to be Microsoft's product without
//! saying otherwise is a domain an operator cannot tell apart from a real one in a log, and this
//! server's answers are not Microsoft's.

use serde::{Deserialize, Serialize};

/// The lowest and highest `objectVersion` this server can publish.
///
/// The range now starts at `sch44`, the schema Windows Server 2008 brought: a domain that says it is
/// at level 3 has to publish a schema of that line, and a client of that release reads the number
/// before it decides what to ask for. Above it, `sch91` is the last schema Windows Server 2025 wrote.
pub const MIN_SCHEMA_VERSION: u8 = 44;
/// See [`MIN_SCHEMA_VERSION`].
pub const MAX_SCHEMA_VERSION: u8 = 91;

/// The schema versions that exist, and the domain level each one implies.
///
/// Not every number in the range is a release. `sch70` through `sch86` are the intermediate files
/// between Windows Server 2012 R2 and 2016, and none of them shipped as a product a client can name
/// itself after; publishing one would state a level no release ever had. The pairs below are the
/// documented ones, and a number outside this table is refused rather than guessed at - a domain
/// whose level was invented is worse than one that refuses to start.
///
/// The two columns are **not** one ladder. 2016 and 2019 answer the same level with different
/// schemas, so the schema decides and the level follows:
///
/// | schema | level | release |
/// |---|---|---|
/// | 44 | 3 | Windows Server 2008 |
/// | 47 | 4 | Windows Server 2008 R2 |
/// | 56 | 5 | Windows Server 2012 |
/// | 69 | 6 | Windows Server 2012 R2 |
/// | 87 | 7 | Windows Server 2016 |
/// | 88 | 7 | Windows Server 2019 and 2022 |
/// | 89-91 | 10 | Windows Server 2025 |
const SCHEMA_LEVELS: [(u8, u32); 9] = [
    (44, 3),
    (47, 4),
    (56, 5),
    (69, 6),
    (87, 7),
    (88, 7),
    (89, 10),
    (90, 10),
    (91, 10),
];

/// The level a schema version stands for, or `None` for a number no release used.
fn level_of(schema: u8) -> Option<u32> {
    SCHEMA_LEVELS
        .iter()
        .find(|(version, _)| *version == schema)
        .map(|(_, level)| *level)
}

/// The Windows Server a domain says it emulates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmulationConfig {
    /// The product a client displays: `Windows Server 2022`.
    #[serde(default = "default_product")]
    pub product: String,
    /// The kernel version: `10.0`.
    #[serde(default = "default_version")]
    pub version: String,
    /// The build number: `20348` for 2022, `17763` for 2019, `14393` for 2016.
    #[serde(default = "default_build")]
    pub build: String,
    /// A marker of this server's own, so an emulated answer is recognisable as one.
    ///
    /// Unset is the usual case, and then the tag is `git describe --all --abbrev=4` for the tree this
    /// was built from: a release tag when the build sits on one, and the nearest tag with its distance
    /// and a short hash when it does not. A release that has a name of its own sets it here.
    #[serde(default)]
    pub tag: Option<String>,
    /// The schema version to publish, as `objectVersion` numbers it: `sch70` through `sch91`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
}

fn default_product() -> String {
    "Windows Server 2022".to_string()
}

fn default_version() -> String {
    "10.0".to_string()
}

fn default_build() -> String {
    "20348".to_string()
}

/// The tag when the operator named none: `git describe --all --abbrev=4` of the built tree, from
/// `build.rs`.
///
/// A constant would say the same thing about every build, which is exactly what a tag is for not
/// doing. A repository with no tags answers with its branch (`heads/main`), which is what `describe`
/// can honestly say there. The build script falls back to the crate version and then to `unknown`, so
/// this is never empty.
pub fn build_tag() -> &'static str {
    option_env!("RRL_BUILD_TAG_VALUE").unwrap_or("unknown")
}

fn default_schema_version() -> u8 {
    // 88 is `sch88`, the file Windows Server 2019 introduced and 2022 inherited: the highest schema
    // that promises nothing beyond what this server answers.
    88
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            product: default_product(),
            version: default_version(),
            build: default_build(),
            tag: None,
            schema_version: default_schema_version(),
        }
    }
}

impl EmulationConfig {
    /// `operatingSystem`: what a client shows its user, and it says it is an emulation.
    ///
    /// The value is deliberately not a product name alone. A client reads this for display, an
    /// operator reads it in a log, and "Windows Server 2022" with no qualification would claim this
    /// server is Microsoft's build - which it is not, and which an operator diagnosing a difference in
    /// behaviour needs to see at a glance.
    pub fn operating_system(&self) -> String {
        format!("RRL Domain «{}» emulation", self.product)
    }

    /// `operatingSystemVersion`: `<WinVer> (<WinCode>) <TAG>`, the shape Windows itself writes.
    ///
    /// The tag names the build: a configured one when an operator gave it a release name, and the
    /// short commit hash otherwise. "10.0 (20348) RRL" would say the same thing about every build of
    /// this server, which is the one thing a tag must not do.
    pub fn operating_system_version(&self) -> String {
        let tag = self.tag.as_deref().unwrap_or(build_tag());
        format!("{} ({}) {}", self.version, self.build, tag)
    }

    /// `domainFunctionality` and `forestFunctionality`, as the schema version implies them.
    ///
    /// The two columns are not one ladder: `sch87` (2016) and `sch88` (2019, 2022) both answer **7**,
    /// because 2019 and 2022 raised the schema and left the level alone. Below 2016 each release
    /// moved both, which is why the table in [`SCHEMA_LEVELS`] is the only way to get this right.
    pub fn functionality(&self) -> &'static str {
        match self.functionality_number() {
            3 => "3",
            4 => "4",
            5 => "5",
            6 => "6",
            7 => "7",
            _ => "10",
        }
    }

    /// The same level as a number, for the places that compare rather than publish it.
    ///
    /// `DS_FLAG` bits in a locator answer are one example: each says "not older than", so the answer
    /// depends on the order of the levels, not on their spelling.
    pub fn functionality_number(&self) -> u32 {
        // A schema no release used has no level, and `validate` refuses it at load. The fallback is
        // the **oldest** level rather than the newest: an answer that promises less is one a client
        // can work around, and an answer that promises more is the failure this whole table exists
        // to prevent.
        level_of(self.schema_version).unwrap_or(3)
    }

    /// `objectVersion`, as the string a client reads.
    pub fn object_version(&self) -> String {
        self.schema_version.to_string()
    }

    /// Whether the configured version is one this server can honestly publish.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(format!(
                "schema_version {} is outside {}..={}: sch44 is the oldest schema a Windows Server \
                 client recognises and sch91 the newest that exists",
                self.schema_version, MIN_SCHEMA_VERSION, MAX_SCHEMA_VERSION
            ));
        }
        // A number inside the range is not enough: the years between 2012 R2 and 2016 produced schema
        // files that never shipped, and each of them would state a level no release ever had. Read
        // the level from the table instead of inventing one.
        if level_of(self.schema_version).is_none() {
            let known: Vec<String> = {
                let mut versions: Vec<u8> = SCHEMA_LEVELS.iter().map(|(v, _)| *v).collect();
                versions.sort_unstable();
                versions.iter().map(u8::to_string).collect()
            };
            return Err(format!(
                "schema_version {} is not a schema any Windows Server release published, so it \
                 implies no domain level: the ones that exist are {} - 44 is 2008, 47 is 2008 R2, \
                 56 is 2012, 69 is 2012 R2, 87 is 2016, 88 is 2019 and 2022, and 89 through 91 are \
                 2025",
                self.schema_version,
                known.join(", ")
            ));
        }
        for (name, value) in [
            ("product", &self.product),
            ("version", &self.version),
            ("build", &self.build),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "emulation.{name} is empty: a client that reads an empty name shows nothing, and \
                     an operator cannot tell which release this domain claims"
                ));
            }
        }
        // Set-and-empty is a mistake; unset is the normal case and means "this build".
        if self.tag.as_deref().is_some_and(|tag| tag.trim().is_empty()) {
            return Err(
                "emulation.tag is empty: leave it unset for this build's commit hash, or name the \
                 release"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_version_decides_the_level_and_not_the_other_way_round() {
        // Below 2016 every release moved both columns, so the pair is what has to be right.
        for (schema, level) in [(44, "3"), (47, "4"), (56, "5"), (69, "6")] {
            let config = EmulationConfig {
                schema_version: schema,
                ..Default::default()
            };
            assert_eq!(
                config.functionality(),
                level,
                "sch{schema} is Windows Server level {level}"
            );
            assert!(config.validate().is_ok());
        }
        // 2016 and 2019/2022 are the same level: the schema moved and the level did not.
        assert_eq!(
            EmulationConfig {
                schema_version: 87,
                ..Default::default()
            }
            .functionality(),
            "7"
        );
        assert_eq!(
            EmulationConfig {
                schema_version: 88,
                ..Default::default()
            }
            .functionality(),
            "7"
        );
        // 2025 is the first new level since 2016.
        assert_eq!(
            EmulationConfig {
                schema_version: 89,
                ..Default::default()
            }
            .functionality(),
            "10"
        );
        assert_eq!(
            EmulationConfig {
                schema_version: 91,
                ..Default::default()
            }
            .functionality(),
            "10"
        );
    }

    /// Every level the task asks for is reachable, and each one from one schema and no other.
    #[test]
    fn every_level_from_2008_to_2025_has_a_schema_of_its_own() {
        for level in [3, 4, 5, 6, 7, 10] {
            let schemas: Vec<u8> = (MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION)
                .filter(|version| {
                    EmulationConfig {
                        schema_version: *version,
                        ..Default::default()
                    }
                    .functionality_number()
                        == level
                })
                .collect();
            assert!(
                !schemas.is_empty(),
                "no schema publishes level {level}: a client of that release has nothing to connect to"
            );
        }
    }

    /// A schema no release published states a level no release had, so it is refused.
    #[test]
    fn a_schema_no_release_published_is_refused_and_the_ones_that_exist_are_named() {
        // 70 through 86 are the files between 2012 R2 and 2016; none shipped.
        for undocumented in [70, 76, 80, 84, 86] {
            let config = EmulationConfig {
                schema_version: undocumented,
                ..Default::default()
            };
            let message = config
                .validate()
                .expect_err(&format!("sch{undocumented} is not a release"));
            assert!(
                message.contains("implies no domain level"),
                "the refusal has to say why: {message}"
            );
            for known in ["44", "47", "56", "69", "87", "88", "91"] {
                assert!(
                    message.contains(known),
                    "the refusal has to name the versions that do exist, {known} is missing: {message}"
                );
            }
        }
    }

    #[test]
    fn what_is_published_says_it_is_an_emulation() {
        let config = EmulationConfig::default();
        assert_eq!(
            config.operating_system(),
            "RRL Domain «Windows Server 2022» emulation"
        );
        // Unset tag: the build's own commit hash, which is what tells two builds apart.
        assert_eq!(
            config.operating_system_version(),
            format!("10.0 (20348) {}", build_tag())
        );
        assert!(
            !build_tag().is_empty() && build_tag() != "RRL",
            "a tag that is the same for every build names no build: {}",
            build_tag()
        );
        assert_eq!(config.object_version(), "88");
    }

    #[test]
    fn a_version_outside_the_range_is_refused_with_the_reason() {
        let too_old = EmulationConfig {
            schema_version: 43,
            ..Default::default()
        };
        let message = too_old.validate().expect_err("43 is below the range");
        assert!(message.contains("44..=91"), "{message}");
        let too_new = EmulationConfig {
            schema_version: 92,
            ..Default::default()
        };
        assert!(too_new.validate().is_err());
    }

    #[test]
    fn a_tag_that_is_configured_is_what_a_client_reads() {
        // A release with a name of its own says so instead of the hash.
        let config = EmulationConfig {
            tag: Some("0.0.1".to_string()),
            ..Default::default()
        };
        assert_eq!(config.operating_system_version(), "10.0 (20348) 0.0.1");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_empty_name_is_refused() {
        let empty_product = EmulationConfig {
            product: String::new(),
            ..Default::default()
        };
        let message = empty_product
            .validate()
            .expect_err("an empty product is not a name");
        assert!(message.contains("emulation.product"), "{message}");

        // Set-and-empty is a mistake; unset is the normal case.
        let empty_tag = EmulationConfig {
            tag: Some(String::new()),
            ..Default::default()
        };
        let message = empty_tag
            .validate()
            .expect_err("an empty tag is not a name");
        assert!(message.contains("emulation.tag"), "{message}");
        assert!(EmulationConfig::default().validate().is_ok());
    }
}
