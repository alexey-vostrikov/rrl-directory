#!/bin/sh
# Run cargo inside the pinned build container.
# Host has no rust toolchain on purpose (see docs/ub-log.md): every build,
# test, fmt, clippy and metrics run goes through this wrapper, so the toolchain
# version is the one pinned in rust-toolchain.toml and the image below.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
# One registry for every Rust project on this machine, named after the base it serves: a registry
# filled under one glibc is one the next toolchain may not be able to use. `RR_LDAP_CARGO_CACHE`
# still overrides it for a one-off run.
cargo_cache="${RR_LDAP_CARGO_CACHE:-rrl-cargo-bullseye}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

# Bullseye, assembled locally: `rust:<version>-bullseye` is not published, and the reason to want
# it is glibc - bullseye gives 2.31, which the stands and Astra Linux run, while bookworm gives 2.36
# and a binary built there will not start. The assembly is `docker/toolchain.Dockerfile`, the same
# file rust-smb-server uses, so the two crates build on one toolchain.
TOOLCHAIN_CHANNEL=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
IMAGE="${RR_LDAP_IMAGE:-rust:${TOOLCHAIN_CHANNEL}-bullseye}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE from docker/toolchain.Dockerfile (once)" >&2
    docker build -f "$repo/docker/toolchain.Dockerfile" -t "$IMAGE" \
        --build-arg "RUST_TOOLCHAIN=${TOOLCHAIN_CHANNEL}" "$repo/docker" >&2
fi

mkdir -p "$target_cache"
case "$cargo_cache" in
/* | .*) mkdir -p "$cargo_cache" ;;
*) docker volume create "$cargo_cache" >/dev/null ;;
esac
case "$rustup_cache" in
/* | .*) mkdir -p "$rustup_cache" ;;
esac

# Both Kerberos dependencies are git dependencies, so there is no sibling checkout to mount: cargo
# fetches `rrl-kdc` and `smb-server` into `$CARGO_HOME/git` and the container needs only that cache,
# which every run already has. The mounts this replaced pointed at paths the manifest no longer
# names, and one of them named a directory that had since been renamed - a mount that resolves to
# nothing is invisible, which is why they are gone rather than left in place.

# MIRIFLAGS is passed through because otherwise `-Zmiri-disable-isolation` is dropped silently, and
# a test that needs the filesystem fails with "mkdir not available when isolation is enabled" - which
# reads as a defect in the code under test rather than in the harness.
# Temporary: a sibling checkout, so a change under test can be built before it is pushed.
extra_mounts=""
if [ -n "${RR_LDAP_EXTRA_MOUNT:-}" ]; then
    for mount in $RR_LDAP_EXTRA_MOUNT; do
        extra_mounts="$extra_mounts -v $mount"
    done
fi

# `RR_LDAP_DEBUG`: how much debug info the build carries. Measured on one test binary of this
# repository, 312M with the default:
#
#     all `.debug_*` sections    247M   (79% of the file)
#     `.debug_line` alone         21M   (the file:line a backtrace needs)
#     stripped                   64M   (4.9x smaller)
#
# So `line-tables-only` keeps a failing test's backtrace with file and line, drops what a debugger
# would show for variables, and is about a quarter of the size. `RR_LDAP_DEBUG=2` restores the full
# default for a session that is chasing a defect through a debugger; `RR_LDAP_DEBUG=0` is the
# smallest and gives the build's own panic messages nothing to point at.
debug_level="${RR_LDAP_DEBUG:-line-tables-only}"

# `CARGO_INCREMENTAL=0`: with the target directory mounted from the host and the toolchain in a
# container, incremental state is rewritten whenever anything about the mount changes and is not
# shared between the feature combinations this repository tests. Measured: 5.7G of a 52G target
# directory, for a saving no run ever collected. `RR_LDAP_INCREMENTAL=1` turns it back on.
#
# `RR_LDAP_PRUNE` (default on): after the command, `scripts/cargo-prune.sh` removes artifacts no run
# has written in `RR_LDAP_PRUNE_AGE` days (default 3) and the incremental tree. `cargo` never deletes
# an artifact it is no longer asked for, and every feature combination is a separate hash, so
# without this the directory only grows. `RR_LDAP_PRUNE=no` disables it for a run that is measuring
# cold-build time.
incremental="${RR_LDAP_INCREMENTAL:-0}"
prune="${RR_LDAP_PRUNE:-yes}"
prune_age="${RR_LDAP_PRUNE_AGE:-3}"

# `ionice`: the build yields I/O bandwidth to everything else, so a twelve-minute test run does not
# make the machine unusable for whoever is using it. A flag string rather than a class, because the
# right one depends on the disk: `-c2 -n7` is best-effort at the lowest priority and still gets
# bandwidth when nothing else wants it, `-c3` is idle and gets none while anything else does - which
# on a busy disk turns a build into a stall. The comment is here because the effect is not obvious:
# I/O priorities are applied by the block scheduler, and a device with `none` (many NVMe drives, this
# one included) ignores them entirely. It is still set: it costs nothing, it applies on the hosts
# where the scheduler does honour it, and it is inherited by every compiler and test process the
# build spawns.
ionice_flags="${RR_LDAP_IONICE:--c2 -n7}"

exec docker run --rm \
  -v "$repo:/w" \
  ${extra_mounts} \
  -v "$cargo_cache:/cargo" \
  -v "$target_cache:/target" \
  -w /w \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e "CARGO_INCREMENTAL=$incremental" \
  -e "CARGO_PROFILE_DEV_DEBUG=$debug_level" \
  -e "CARGO_PROFILE_TEST_DEBUG=$debug_level" \
  -e "RR_LDAP_PRUNE=$prune" \
  -e "RR_LDAP_PRUNE_AGE=$prune_age" \
  -e "RR_LDAP_IONICE=$ionice_flags" \
  -e "MIRIFLAGS=${MIRIFLAGS:-}" \
  "$IMAGE" sh -c '
    # `ionice` where it is available and permitted, the command alone where it is not: a build that
    # refuses to start because a priority could not be set would be worse than a build that competes
    # for the disk.
    #
    # shellcheck disable=SC2086 # a flag string, word-split on purpose
    if ionice $RR_LDAP_IONICE true 2>/dev/null; then
      set -- ionice $RR_LDAP_IONICE "$@"
    fi
    "$@"
    status=$?
    # After the command, and whatever it did: a run that failed has already written the artifacts of
    # the units it got through, and those are the ones that accumulate. The prune deletes thousands
    # of files, so it carries the same priority.
    case "${RR_LDAP_PRUNE:-yes}" in
      no | NO | 0 | false) ;;
      *) ionice $RR_LDAP_IONICE /w/scripts/cargo-prune.sh "$RR_LDAP_PRUNE_AGE" >&2 || true ;;
    esac
    exit $status
  ' sh cargo "$@"
