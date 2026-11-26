#!/bin/sh
# Free the space a build leaves behind, without throwing away what the next run needs.
#
# Why this exists: `cargo` never deletes an artifact it is no longer asked for. Every feature
# combination gets its own metadata hash, so `--features kdc`, `--features smb` and `--all-features`
# each keep a full set of rlibs and test binaries side by side, and a target directory served to
# every one of those runs grows without a ceiling. Measured on this repository: 52G, of which
# 39G sat in `debug/deps` and 5.7G in `debug/incremental`.
#
# What it removes, and why each is safe:
#
#   * `deps` and `build` entries whose file was not written in AGE days. A stale artifact is one
#     whose unit has not been built since - if a later run needs it, `cargo` rebuilds it from source
#     and the only cost is that rebuild. Nothing about correctness depends on these files existing.
#   * `incremental`, entirely and always: with a target directory mounted from the host and a
#     toolchain in a container, incremental state is rebuilt whenever anything about the mount
#     changes, and it is not reused across the feature combinations this repository tests. It is
#     5.7G of a 52G directory.
#
# What it does NOT remove: the `cargo` registry cache (the downloaded crates and the git checkouts
# of `rrl-kdc` and `smb-server`). Those are inputs, not outputs; deleting them turns a rebuild into a
# download.
#
# Usage:
#   scripts/cargo-prune.sh            # AGE defaults to 3 days
#   scripts/cargo-prune.sh 1          # keep only what was written today
#   scripts/cargo-prune.sh --dry-run  # say what would go, remove nothing
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
# The target directory this prunes. `CARGO_TARGET_DIR` first, because that is what the script sees
# when it runs inside the build container where the host's target is mounted at `/target`; the
# `~/.cache/rrl/target` default is the same directory as `scripts/cargo.sh` names on the host.
target_cache="${RR_LDAP_TARGET_CACHE:-${CARGO_TARGET_DIR:-$HOME/.cache/rrl/target}}"

dry_run=""
age=""
for argument in "$@"; do
    case "$argument" in
    --dry-run) dry_run=yes ;;
    *[!0-9]*) echo "cargo-prune: '$argument' is not a number of days" >&2; exit 2 ;;
    *) age="$argument" ;;
    esac
done
age="${age:-3}"

if [ ! -d "$target_cache" ]; then
    echo "cargo-prune: $target_cache does not exist, nothing to do"
    exit 0
fi

# `du -sk` before and after, because the number an operator wants is the one that changed.
before=$(du -sk "$target_cache" 2>/dev/null | cut -f1)

# `! -newermt` rather than `-mtime`: on a bind-mounted directory the mtime of an old artifact can be
# older than any `-mtime` bucket the tool will look at, and the two disagree in a way that silently
# finds nothing. `! -newermt "<N> days ago"` asks the question directly.
cutoff="$age days ago"

remove() {
    # Counted before deleting, and in both modes: a run that says "0 files removed" when it removed
    # ten thousand is a run that teaches the operator to stop reading the message. `-print | wc -l`
    # and then a second walk, because `find -delete` reports nothing back.
    count=$(find "$@" -type f -print 2>/dev/null | wc -l)
    if [ -z "$dry_run" ]; then
        find "$@" -type f -delete 2>/dev/null || true
    fi
    echo "$count"
}

removed=0
# Before anything is deleted, the profile directory's lock is taken: `cargo` holds
# `<target>/<profile>/.cargo-lock` for the length of a build, so a prune that waits on the same lock
# never runs inside one.
#
# This is not caution, it is a defect that was measured. `find -type d -empty -delete` below used to
# run unconditionally, and a second gate started while the first was still building deleted
# `.fingerprint/<crate>/` a moment after cargo created it and a moment before cargo wrote into it:
#
#     error: failed to write `/target/debug/.fingerprint/x25519-dalek-.../invoked.timestamp`
#     Caused by: No such file or directory
#
# Two runs sharing one target directory is a thing that happens here - it is what the wrapper mounts
# for every invocation - so the lock has to be taken, and the empty-directory sweep has to go: its
# only benefit was a tidier `du`, and its cost was breaking somebody else's build.
locked=""
for profile in debug release; do
    lock="$target_cache/$profile/.cargo-lock"
    [ -d "$target_cache/$profile" ] || continue
    # `-w 60`: a build that holds the lock longer than a minute is one this prune has no business
    # racing. Said out loud rather than silently skipped, because a prune that never runs and never
    # says so is how the directory grew in the first place.
    #
    # No `2>/dev/null` on that `exec`: a redirection-only `exec` applies to the shell itself and for
    # the rest of the script, so silencing it here silenced every message below - measured, as a
    # prune that printed nothing at all and exited 0 while the lock was held.
    exec 9>"$lock" || continue
    if flock -w 60 9; then
        locked="$profile"
    else
        echo "cargo-prune: $profile is locked by a running build, skipping it" >&2
        exec 9>&-
        continue
    fi
    break
done

if [ -z "$locked" ]; then
    echo "cargo-prune: nothing to prune (no unlocked profile directory under $target_cache)" >&2
    exit 0
fi

for dir in debug/deps debug/build release/deps release/build; do
    [ -d "$target_cache/$dir" ] || continue
    count=$(remove "$target_cache/$dir" ! -newermt "$cutoff")
    removed=$((removed + count))
    echo "cargo-prune: $dir: $count files older than $age days"
done

# Incremental state always goes: see the header. `debug/incremental` is per-crate directories, so
# removing the tree is both faster and more complete than walking it.
for dir in debug/incremental release/incremental; do
    [ -d "$target_cache/$dir" ] || continue
    if [ -n "$dry_run" ]; then
        echo "cargo-prune: $dir: would remove the whole tree ($(du -sh "$target_cache/$dir" | cut -f1))"
    else
        rm -rf "${target_cache:?}/$dir"
        echo "cargo-prune: $dir: removed"
    fi
done

after=$(du -sk "$target_cache" 2>/dev/null | cut -f1)
freed=$((before - after))
echo "cargo-prune: $target_cache: $((after / 1024))M now, $((freed / 1024))M freed, $removed files"
