"""Revision operations — `EXTENSION-REVISION` §4, through `entity_sdk.revision`.

These run against a real peer with the real revision handler, so what they
assert is the wire the handler accepts rather than a fixture agreeing with the
wrapper that built it.

A large fraction of them exist for one reason: `SDK-EXTENSION-OPERATIONS` §4 —
*the document an SDK author reads* — disagrees with `EXTENSION-REVISION` in
seventeen places (SA-PY-5 / SA-PY-6), and the dangerous rows are the ones that
fail **silently**. Those are pinned here as proof-against-the-engine tests: each
drives the handler with the SDK doc's spelling and shows what it actually
returns, which is what made SA-2/-3/-4 decidable rather than arguable.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    BadRequest,
    EntityClient,
    content_hash,
    find_ancestor,
    revision,
)
from entity_sdk.revision import REVISION_PATTERN, RevisionClient

BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}

PREFIX = "project/"
FILE_TYPE = "test/file"


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def ctx(peer) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=BLANKET,
        caller_capability=BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )


@pytest.fixture
def client(peer, ctx) -> EntityClient:
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


@pytest.fixture
def rev(client) -> RevisionClient:
    return client.revision(PREFIX)


async def _write(client: EntityClient, name: str, content: str) -> bytes:
    return await client.put(PREFIX + name, FILE_TYPE, {"c": content})


async def _raw(client: EntityClient, operation: str, data: dict) -> dict:
    """Dispatch straight at the handler, bypassing the wrapper's decoding.

    The proof-against-the-engine tests need the undecoded body: the point of
    each is what the *handler* does with a spelling, not what the SDK makes of
    the answer.
    """
    result = await client.execute(
        REVISION_PATTERN,
        operation,
        {"type": f"system/revision/{operation}-params", "data": data},
        resource_targets=[REVISION_PATTERN],
    )
    if isinstance(result, dict) and result.get("type") == "system/envelope":
        return (result.get("data") or {}).get("root", {}).get("data") or {}
    return (result or {}).get("data") or {}


# =============================================================================
# The lifecycle
# =============================================================================


class TestTheVersionLifecycle:
    @pytest.mark.asyncio
    async def test_commit_status_and_log(self, client, rev):
        await _write(client, "a.txt", "one")
        first = await rev.commit()

        assert isinstance(first.version, bytes) and len(first.version) == 33
        assert isinstance(first.root, bytes)

        state = await rev.status()
        assert state.head == first.version
        assert state.has_versions
        assert state.conflicts == 0
        assert state.prefix == PREFIX

        await _write(client, "b.txt", "two")
        second = await rev.commit()
        assert second.version != first.version

        page = await rev.log()
        assert page.versions[0] == second.version
        assert first.version in page.versions
        assert page.has_more is False
        # The envelope's included map is unwrapped onto the page, so the DAG
        # structure is reachable without a second round trip.
        assert page.parents_of(second.version) == [first.version]

    @pytest.mark.asyncio
    async def test_a_commit_that_changes_nothing_returns_the_current_head(self, client, rev):
        await _write(client, "a.txt", "one")
        first = await rev.commit()
        again = await rev.commit()
        assert again.version == first.version, "§6.2 dedup — no redundant entry"

    @pytest.mark.asyncio
    async def test_status_before_any_commit_reports_no_head(self, rev):
        state = await rev.status()
        assert state.head is None
        assert state.has_versions is False
        assert state.is_clean

    @pytest.mark.asyncio
    async def test_the_peer_really_does_encode_that_absence_as_a_zero_hash(self, client, rev):
        """The absorption behind `head is None` — and why it has to exist.

        The peer encodes "no versions" as the canonical 33-byte zero hash to
        match the Go and Rust peers, not by omitting the field the way
        `EXTENSION-REVISION` §2.5 describes. A caller who forwarded that value
        as a version hash would get a 404 from somewhere else entirely, so the
        SDK reads it as absence once, here — the CAP-6 lesson, applied to a
        field we receive rather than one we mint.
        """
        body = await _raw(client, "status", {"prefix": PREFIX})
        assert body["head"] == b"\x00" * 33
        assert (await rev.status()).head is None

    @pytest.mark.asyncio
    async def test_a_prefix_must_end_in_a_slash(self, client):
        with pytest.raises(BadRequest) as exc:
            client.revision("project")
        assert "project/" in str(exc.value)


# =============================================================================
# SA-PY-5 — the §4 spellings that fail silently
# =============================================================================


class TestTheSDKDocSpellingsThatFailSilently:
    @pytest.mark.asyncio
    async def test_the_sdk_docs_count_would_have_returned_the_whole_dag(self, client, rev):
        """§4 spells `log`'s page size `count`; the handler reads `limit`.

        This is the SA-PY-2 shape again: an unknown parameter is not an error,
        so paging built from §4 does not fail — it silently returns everything.
        On a large DAG that is a transfer bug wearing no costume at all.
        """
        for i in range(4):
            await _write(client, "a.txt", f"v{i}")
            await rev.commit()

        with_count = await _raw(client, "log", {"prefix": PREFIX, "count": 1})
        with_limit = await _raw(client, "log", {"prefix": PREFIX, "limit": 1})

        assert len(with_count["versions"]) == 4, "count= was ignored, as filed"
        assert len(with_limit["versions"]) == 1
        assert with_count.get("has_more") is not True

    @pytest.mark.asyncio
    async def test_count_is_absorbed_so_either_document_pages(self, client, rev):
        for i in range(3):
            await _write(client, "a.txt", f"v{i}")
            await rev.commit()

        by_extension = await rev.log(limit=1)
        by_sdk_doc = await rev.log(count=1)

        assert len(by_extension) == 1
        assert by_sdk_doc.versions == by_extension.versions
        assert by_sdk_doc.has_more is True

    @pytest.mark.asyncio
    async def test_passing_both_spellings_is_refused_rather_than_silently_halved(self, rev):
        with pytest.raises(BadRequest) as exc:
            await rev.log(limit=2, count=5)
        assert "SA-PY-5" in str(exc.value)

    @pytest.mark.asyncio
    async def test_the_sdk_docs_exclude_patterns_is_a_field_nothing_reads(self, client):
        """§4's prefix config spells the exclude list `exclude_patterns`.

        §2.4 spells it `exclude`. An unknown field is carried, not rejected, so
        the config lands and returns 200 with the caller's exclusions in a key
        no consumer looks at.

        The engine says so itself at the one place excludes are load-bearing
        today: §4.4.17's V2 refuses `auto_version: true` on a prefix that
        encompasses the engine's own paths unless the required patterns are in
        `exclude`. Spelled §4's way, the same config is refused — the excludes
        are right there in the request and the validator cannot see them.
        """
        required = [
            "system/revision/*",
            "system/tree/root/*",
            "system/tree/tracking-config/*",
            "system/history/*",
            "system/clock/*",
        ]

        def config(field: str) -> dict:
            return {
                "name": "root",
                "action": "set",
                "config": {
                    "type": "system/revision/config",
                    "data": {"prefix": "/", "auto_version": True, field: required},
                },
            }

        with pytest.raises(BadRequest) as exc:
            await _raw(client, "config", config("exclude_patterns"))
        assert exc.value.code == "config/missing-required-exclude"

        landed = await _raw(client, "config", config("exclude"))
        assert landed["config_path"].endswith("/config")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad", ["**", "a/**/b", "a*b", "*a*", "system/revision/**"]
    )
    async def test_a_pattern_outside_the_four_forms_is_refused_at_config_write(
        self, client, bad
    ):
        """`REV-GLOB-REJECT-1/2` at the wire, not at the predicate.

        `validate_exclude_pattern` is unit-pinned in
        `tests/unit/test_revision_exclude_glob.py`; a passing predicate says
        nothing about the **status and code** a peer answers, which is the only
        thing a cross-impl probe can see. This drives the §4.4.17 surface and
        asserts both.

        Note `auto_version` is absent: V6 is deliberately ungated by it, so a
        config that never reaches V2/V3 still cannot store a pattern this peer
        cannot evaluate.
        """
        with pytest.raises(BadRequest) as exc:
            await _raw(client, "config", {
                "name": "glob-reject",
                "action": "set",
                "config": {
                    "type": "system/revision/config",
                    "data": {"prefix": "glob-reject/", "exclude": [bad]},
                },
            })
        assert exc.value.status == 400
        assert exc.value.code == "config/invalid-exclude-pattern"

    @pytest.mark.asyncio
    async def test_the_acceptance_control_beside_it(self, client):
        """The teeth control: a valid form-2 pattern MUST be accepted.

        Without it, every rejection above is attributable to a peer that
        refuses all configs rather than to the grammar — which is the same
        control `entity-core-go`'s probe runs first, and for the same reason.
        """
        landed = await _raw(client, "config", {
            "name": "glob-accept",
            "action": "set",
            "config": {
                "type": "system/revision/config",
                "data": {"prefix": "glob-accept/", "exclude": ["tmp/*"]},
            },
        })
        assert landed["config_path"].endswith("/config")

    @pytest.mark.asyncio
    async def test_exclude_types_is_held_to_the_same_grammar(self, client):
        """§2.4's `subject` is the type name for `exclude_types`, and the forms
        do not change with the subject — so V6 must read both fields. A gate
        that budgets one of two fields reports the other as clean."""
        with pytest.raises(BadRequest) as exc:
            await _raw(client, "config", {
                "name": "glob-types",
                "action": "set",
                "config": {
                    "type": "system/revision/config",
                    "data": {"prefix": "glob-types/", "exclude_types": ["app/**"]},
                },
            })
        assert exc.value.code == "config/invalid-exclude-pattern"

    @pytest.mark.asyncio
    async def test_exclude_patterns_is_absorbed_at_this_boundary(self, client):
        """Same config, same validator, through the wrapper — and it lands.

        The root prefix is the point: it is the case where V2 actually reads
        the exclude list, so a translation that did not happen would show up
        as the 400 above rather than as a passing test.
        """
        result = await client.revision("/").set_config(
            "everything",
            auto_version=True,
            exclude_patterns=[
                "system/revision/*",
                "system/tree/root/*",
                "system/tree/tracking-config/*",
                "system/history/*",
                "system/clock/*",
            ],
        )
        assert result["tracking_config_action"] == "created"

    @pytest.mark.asyncio
    async def test_commit_applies_config_excludes(self, client, rev):
        """§2.4 *"Exclude applies to trie building"* — a MUST we applied nowhere.

        Filed as **SA-PY-8** and ruled confirmed by arch
        (`ROUTING-2026-08-18-c` §3): a version entry's `root` MUST be the
        exclude-filtered trie, on every path that emits one. Establishing it
        turned up that §6.1 contradicts itself independently of any
        implementation — its Amendment-2 paragraph requires the new version's
        trie to carry explicit entries for every path in the parent's, which an
        algorithm assigning `root = current_tracked_root(prefix)` can never do
        because it builds no trie. The Algorithm block is the stale half, so
        filtering is not a new constraint; it is what the rest of §6.1 already
        required.

        This was the pin, inverted. It previously asserted the two roots were
        **equal** — the characterization of our own defect — with the note
        "flip this test when both land". Both landed:
        `compute_versioned_bindings` at `commit`, and the filtered trie as the
        auto-version root (D1), which is the half that matters more because
        suppressing the version *entry* for an excluded write never suppressed
        that path's contribution to the tracked root. One write later, the
        root committed to data the config says is not versioned.

        `entity-core-go` is at no fault here and their row should be read as a
        spec revision rather than a defect report: filtering at `commit` and
        not at auto-version is exactly what the text said.
        """
        await _write(client, "a.txt", "keep")
        await _write(client, "ephemeral/scratch", "drop")

        before = await rev.commit()

        await rev.set_config("project", exclude=["ephemeral/*"])
        await _write(client, "a.txt", "keep-2")
        await _write(client, "a.txt", "keep")
        after = await rev.commit()
        without_config, with_exclude = before.root, after.root

        assert with_exclude != without_config, (
            "the same tree state produced the same root with and without an "
            "`ephemeral/*` exclude — §2.4's filter is not reaching the trie"
        )

        # The load-bearing half. A root that merely *differs* would also be
        # produced by filtering the wrong thing, so name which path moved:
        # `ephemeral/scratch` leaves the versioned set, `a.txt` — written twice
        # and returned to its original content — does not.
        delta = await rev.diff(before.version, after.version)
        assert "ephemeral/scratch" in delta.removed, (
            f"the excluded path is still versioned (removed={sorted(delta.removed)}, "
            f"changed={sorted(delta.changed)})"
        )
        assert "a.txt" not in delta.removed and "a.txt" not in delta.changed, (
            f"the exclude reached a path it does not name (removed="
            f"{sorted(delta.removed)}, changed={sorted(delta.changed)})"
        )

    @pytest.mark.asyncio
    async def test_merge_strategy_is_refused_and_names_the_operation_that_takes_it(self, rev):
        """The one §4 row this boundary will not absorb.

        `merge_strategy` is listed as a prefix-config field. It is not one:
        merge strategy is per-path or per-type and lives in a different
        namespace written by a different operation. Absorbing it would mean
        picking a target the caller did not name; refusing it costs one error
        message and points at `set_merge_config`.
        """
        with pytest.raises(BadRequest) as exc:
            await rev.set_config("x", merge_strategy="three-way")
        assert "set_merge_config" in str(exc.value)
        assert "SA-PY-5" in str(exc.value)


# =============================================================================
# Merge — and the status field §4 types as a uint
# =============================================================================


async def _diverge(client: EntityClient, rev: RevisionClient) -> tuple[bytes, bytes, bytes]:
    """Build a fork: (base, ours, theirs) with both sides editing `a.txt`."""
    await _write(client, "a.txt", "base")
    base = (await rev.commit()).version

    await rev.create_branch("feature", start=base)

    await _write(client, "a.txt", "theirs")
    theirs = (await rev.commit()).version

    await rev.checkout(branch="feature")
    await _write(client, "a.txt", "ours")
    ours = (await rev.commit()).version

    return base, ours, theirs


class TestMerge:
    @pytest.mark.asyncio
    async def test_a_merge_with_nothing_to_do_is_already_in_sync(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version

        result = await rev.merge(head)
        assert result.status == "already_in_sync"
        assert result.is_clean
        assert result.has_conflicts is False

    @pytest.mark.asyncio
    async def test_theirs_is_absorbed_from_the_sdk_doc(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version

        result = await rev.merge(theirs=head)
        assert result.status == "already_in_sync"

    @pytest.mark.asyncio
    async def test_a_conflicting_merge_reports_a_string_status_never_409(self, client, rev):
        """SA-PY-5's most dangerous row, proved against the engine.

        §4 types `MergeResult.status` as a uint — *200 clean, 409 conflicts*.
        The extension types it as a string with nine values. So
        ``if result.status == 409: resolve_conflicts()`` never fires, and a
        merge that left unresolved conflicts in the tree reads as clean. There
        is no exception, no bad field, nothing to debug — just a branch that
        never runs.
        """
        _, _, theirs = await _diverge(client, rev)

        body = await _raw(client, "merge", {"prefix": PREFIX, "remote_version": theirs})
        assert body["status"] == "merged_with_conflicts"
        assert body["status"] not in (200, 409)
        assert body["conflicts"] == ["a.txt"], "trie-relative paths, not absolute"

        state = await rev.status()
        assert state.conflicts == 1, "the tree really is conflicted"

    @pytest.mark.asyncio
    async def test_the_wrapper_surfaces_conflicts_as_a_predicate(self, client, rev):
        _, _, theirs = await _diverge(client, rev)

        result = await rev.merge(theirs)
        assert result.has_conflicts
        assert result.is_clean is False
        assert result.conflicts == ["a.txt"]

    @pytest.mark.asyncio
    async def test_a_dry_run_previews_without_writing(self, client, rev):
        _, _, theirs = await _diverge(client, rev)

        preview = await rev.merge(theirs, dry_run=True)
        assert preview.status == "would_conflict"
        assert preview.dry_run is True
        assert preview.applied is False
        assert (await rev.status()).conflicts == 0, "a preview leaves no conflicts"

    @pytest.mark.asyncio
    async def test_merge_requires_a_hash(self, rev):
        with pytest.raises(BadRequest):
            await rev.merge("not-a-hash")


class TestResolve:
    @pytest.mark.asyncio
    async def test_resolving_clears_the_conflict(self, client, rev):
        _, _, theirs = await _diverge(client, rev)
        merged = await rev.merge(theirs)
        assert merged.conflicts == ["a.txt"]

        winner = content_hash(FILE_TYPE, {"c": "ours"})
        result = await rev.resolve("a.txt", winner)

        assert result.path == "a.txt"
        assert result.resolved == winner
        assert result.remaining_conflicts == 0
        assert result.all_resolved
        assert (await rev.status()).conflicts == 0

    @pytest.mark.asyncio
    async def test_resolving_by_deletion_unbinds_the_path(self, client, rev):
        _, _, theirs = await _diverge(client, rev)
        await rev.merge(theirs)

        result = await rev.resolve("a.txt", None)
        assert result.resolved is None
        assert result.all_resolved
        assert await client.has(PREFIX + "a.txt") is False

    @pytest.mark.asyncio
    async def test_resolve_refuses_an_entity_and_says_what_to_pass(self, rev):
        """§4 types `resolution` as an `Entity`; the handler takes a hash.

        Absorbing this one would mean hashing an entity the peer has never
        seen and handing it a hash it cannot resolve — a 404 from the content
        store, one layer away from the mistake. The refusal names the fix.
        """
        with pytest.raises(BadRequest) as exc:
            await rev.resolve("a.txt", {"type": FILE_TYPE, "data": {"c": "x"}})
        assert "content store" in str(exc.value)


# =============================================================================
# SA-PY-6 — branches are handler state, not tree data
# =============================================================================


class TestBranchesAreHandlerStateNotTreeData:
    @pytest.mark.asyncio
    async def test_a_branch_written_at_the_sdk_docs_path_is_invisible(self, client, rev):
        """§4 lists branches under *Tree Data (not handler operations)*.

        It gives the path as ``system/revision/branches/{name}``. The handler
        stores them at ``system/revision/{H}/branches/{name}`` — ``{H}`` being
        the prefix hash, because branches are per-prefix and the unhashed path
        cannot say which prefix it means.

        A branch written §4's way therefore lands, returns 200, is readable
        back with `get`, and does not exist as far as every revision operation
        is concerned. §4.3 additionally says external callers should not hold
        `put` on that namespace at all — the operation is the write path.
        """
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version

        await client.put(
            "system/revision/branches/main", "system/hash", {"hash": head}
        )
        assert await client.has("system/revision/branches/main")

        listing = await rev.branches()
        assert "main" not in listing, "the handler never looks at that path"

        await rev.create_branch("main")
        assert "main" in await rev.branches()

    @pytest.mark.asyncio
    async def test_branch_lifecycle(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version

        assert await rev.create_branch("feature") == head
        listing = await rev.branches()
        assert listing.branches["feature"] == head
        assert len(listing) == 1

        await rev.delete_branch("feature")
        assert "feature" not in await rev.branches()

    @pytest.mark.asyncio
    async def test_tag_lifecycle(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version

        assert await rev.create_tag("v1") == head
        assert (await rev.tags()).tags == {"v1": head}

        await rev.delete_tag("v1")
        assert len(await rev.tags()) == 0


# =============================================================================
# Checkout — the result shape §4.5 asks for
# =============================================================================


class TestCheckout:
    @pytest.mark.asyncio
    async def test_the_result_reports_the_target_and_the_resulting_head(self, client, rev):
        """§4.5 `checkout-result` is `{status, target_version, head, branch?}`.

        This peer emitted a single `version` field until 2026-08-17 — the shape
        `entity-core-go` still emits and `entity-core-rust` keeps only as a
        compat alias beside the spec pair. Nothing caught it: go's cross-impl
        checkout probe reads `status` and stops.

        Under `auto_version: false` the two fields are equal, which is exactly
        why one field looked sufficient. Under `auto_version: true` they are
        not: checkout becomes state restoration, applying the bindings mints
        versions, and `head` ends up a new descendant of `target_version`.
        """
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "a.txt", "two")
        second = (await rev.commit()).version
        assert first != second

        result = await rev.checkout(version=first)

        assert result.status == "checked_out"
        assert result.target_version == first
        assert result.head == first
        assert result.created_intermediates is False
        assert (await rev.status()).head == first

    @pytest.mark.asyncio
    async def test_under_auto_version_the_head_is_not_the_target(self, client, rev):
        """The case the single `version` field could not express.

        With auto-versioning on, checkout is state restoration: the bindings it
        applies are ordinary writes, each producing a version entry, so the
        prefix ends at a **new** version descending from the one requested
        (§4.4.12). The old result reported the requested version and called it
        the outcome — a peer that had moved somewhere else while telling the
        caller where it had been asked to go.
        """
        await rev.set_config("project", auto_version=True)
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "a.txt", "two")
        assert (await rev.status()).head != first

        result = await rev.checkout(version=first)

        assert result.target_version == first
        assert result.head != first
        assert result.created_intermediates
        assert (await rev.status()).head == result.head, (
            "`head` is where the prefix actually is — it is what a caller "
            "should display"
        )

    @pytest.mark.asyncio
    async def test_checkout_switches_the_tree_contents(self, client, rev):
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "b.txt", "two")
        await rev.commit()
        assert await client.has(PREFIX + "b.txt")

        await rev.checkout(version=first)
        assert await client.has(PREFIX + "b.txt") is False
        assert await client.has(PREFIX + "a.txt")

    @pytest.mark.asyncio
    async def test_checkout_by_branch_records_the_branch(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version
        await rev.create_branch("feature")

        result = await rev.checkout(branch="feature")
        assert result.branch == "feature"
        assert result.target_version == head

    @pytest.mark.asyncio
    async def test_checkout_takes_exactly_one_selector(self, rev):
        with pytest.raises(BadRequest):
            await rev.checkout()
        with pytest.raises(BadRequest):
            await rev.checkout(branch="a", version=b"\x00" * 33)


# =============================================================================
# Diff, cherry-pick, revert
# =============================================================================


class TestDiff:
    @pytest.mark.asyncio
    async def test_diff_reports_added_removed_and_changed(self, client, rev):
        await _write(client, "keep.txt", "same")
        await _write(client, "gone.txt", "bye")
        await _write(client, "edit.txt", "before")
        base = (await rev.commit()).version

        await client.remove(PREFIX + "gone.txt")
        await _write(client, "edit.txt", "after")
        await _write(client, "new.txt", "hello")
        target = (await rev.commit()).version

        diff = await rev.diff(base, target)
        assert set(diff.added) == {"new.txt"}
        assert set(diff.removed) == {"gone.txt"}
        assert set(diff.changed) == {"edit.txt"}
        assert diff.changed["edit.txt"]["base_hash"] != diff.changed["edit.txt"]["target_hash"]
        assert diff.is_empty is False
        assert len(diff) == 3

    @pytest.mark.asyncio
    async def test_diff_accepts_a_branch_name_on_either_side(self, client, rev):
        await _write(client, "a.txt", "one")
        base = (await rev.commit()).version
        await rev.create_branch("start")
        await _write(client, "a.txt", "two")
        target = (await rev.commit()).version

        by_name = await rev.diff("start", target)
        assert by_name.base == base
        assert set(by_name.changed) == {"a.txt"}


class TestCherryPickAndRevert:
    @pytest.mark.asyncio
    async def test_revert_undoes_a_versions_change(self, client, rev):
        await _write(client, "a.txt", "one")
        await rev.commit()
        await _write(client, "a.txt", "two")
        second = (await rev.commit()).version

        result = await rev.revert(second)
        assert result.status == "reverted"
        assert result.reverted == second
        assert result.version is not None
        assert result.has_conflicts is False

        restored = await client.get(PREFIX + "a.txt")
        assert restored["data"]["c"] == "one"

    @pytest.mark.asyncio
    async def test_cherry_pick_applies_one_versions_delta(self, client, rev):
        await _write(client, "a.txt", "one")
        base = (await rev.commit()).version
        await _write(client, "b.txt", "added-later")
        with_b = (await rev.commit()).version

        await rev.checkout(version=base)
        assert await client.has(PREFIX + "b.txt") is False

        result = await rev.cherry_pick(with_b)
        assert result.status == "cherry_picked"
        assert result.source == with_b
        assert await client.has(PREFIX + "b.txt")


# =============================================================================
# Transfer
# =============================================================================


class TestTransfer:
    @pytest.mark.asyncio
    async def test_fetch_returns_the_dag_and_bundles_the_entries(self, client, rev):
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "a.txt", "two")
        second = (await rev.commit()).version

        result = await rev.fetch()
        assert result.head == second
        assert result.versions[0] == second
        assert first in result.versions
        # §4.4.6: version entries *and* their root trie nodes, depth 1.
        assert second in result.entities
        assert result.entities[second]["type"] == "system/revision/entry"
        root = result.entities[second]["data"]["root"]
        assert root in result.entities

    @pytest.mark.asyncio
    async def test_fetch_since_is_a_stop_marker(self, client, rev):
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "a.txt", "two")
        second = (await rev.commit()).version

        result = await rev.fetch(since=first)
        assert result.versions == [second], "the walk stops at `since`, exclusive"

    @pytest.mark.asyncio
    async def test_fetch_entities_is_scoped_to_a_trie_root(self, client, rev):
        await _write(client, "a.txt", "one")
        commit = await rev.commit()
        wanted = content_hash(FILE_TYPE, {"c": "one"})

        result = await rev.fetch_entities(commit.root, [wanted])
        assert result.found == [wanted]
        assert result.missing == []
        assert result.entities[wanted]["data"]["c"] == "one"

    @pytest.mark.asyncio
    async def test_a_hash_outside_the_snapshot_comes_back_missing(self, client, rev):
        await _write(client, "a.txt", "one")
        commit = await rev.commit()
        stranger = content_hash(FILE_TYPE, {"c": "never-committed"})

        result = await rev.fetch_entities(commit.root, [stranger])
        assert result.missing == [stranger]
        assert result.found == []

    @pytest.mark.asyncio
    async def test_fetch_entities_requires_the_snapshot_the_sdk_doc_omits(self, rev):
        """§4's signature is `fetch_entities(peer, hashes)` — no snapshot.

        The snapshot is what stops `fetch-entities` being an open proxy onto
        the content store (§4.4.7), so it is not optional. The handler answers
        400; the wrapper says so without the round trip, and says why.
        """
        with pytest.raises(BadRequest) as exc:
            await rev.fetch_entities(None, [b"\x00" * 33])
        assert "snapshot" in str(exc.value)

    @pytest.mark.asyncio
    async def test_fetch_diff_bundles_the_changed_closure(self, client, rev):
        await _write(client, "a.txt", "one")
        await rev.commit()

        closure = await rev.fetch_diff()
        assert closure, "base=None asks for the full closure (the bootstrap case)"
        assert content_hash(FILE_TYPE, {"c": "one"}) in closure


# =============================================================================
# find-ancestor
# =============================================================================


class TestFindAncestor:
    @pytest.mark.asyncio
    async def test_it_finds_the_fork_point(self, client, rev):
        base, ours, theirs = await _diverge(client, rev)
        assert await find_ancestor(client, ours, theirs) == base

    @pytest.mark.asyncio
    async def test_a_version_is_its_own_ancestor_with_itself(self, client, rev):
        await _write(client, "a.txt", "one")
        head = (await rev.commit()).version
        assert await find_ancestor(client, head, head) == head


# =============================================================================
# SA-PY-7 — `since` names two opposite things
# =============================================================================


class TestSinceMeansTwoThingsAcrossTwoSections:
    @pytest.mark.asyncio
    async def test_log_takes_start_at_and_fetch_keeps_since(self, client, rev):
        """SA-PY-7, ruled: the divergence this pinned is gone by construction.

        `EXTENSION-REVISION` §4.4.2 called `log`'s anchor *"start after this
        version"* — a paging cursor toward the root — while §4.4.6 called
        `fetch`'s identically-named field a stop marker pointing forward from
        HEAD. Opposite ends of the same walk, one name, and the two peers split
        exactly as the two sentences did: this one started the walk *at*
        `since`, `entity-core-go` walked from HEAD and skipped it.

        Neither was provably wrong against the text, which is why the fix was
        to remove the collision rather than pick an inclusivity. `log` now
        takes **`start_at`** (inclusive, walks older) and `fetch` keeps
        **`since`** (exclusive, walks newer). A caller can no longer carry the
        intuition from one operation to the other, because the field they
        would type does not exist there.
        """
        await _write(client, "a.txt", "one")
        first = (await rev.commit()).version
        await _write(client, "a.txt", "two")
        second = (await rev.commit()).version

        page = await rev.log(start_at=first)
        assert page.versions == [first], "start_at is the inclusive anchor, walking older"
        assert second not in page.versions

        # And the operation that kept `since` still means the other thing.
        assert list((await rev.fetch(since=first)).versions) == [second]


# =============================================================================
# The wire this wrapper sends
# =============================================================================


class _Recorder:
    """A stand-in client that records dispatches instead of making them.

    `pull` and `push` reach a second peer, so their handler paths need two live
    peers to exercise end to end (`test_fetch_diff_merge_roundtrip.py` does
    that at the handler layer). What is worth pinning *here* is narrower and is
    exactly what SA-PY-5 is about: that the parameter names this wrapper puts
    on the wire are the extension's.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def execute(self, target, operation, params=None, **kw):
        self.calls.append((target, operation, params or {}))
        return {"type": "system/revision/push-result", "data": {"status": "pushed"}}


class TestTheWireWeSend:
    @pytest.mark.asyncio
    async def test_push_sends_remote_and_prefix_by_their_extension_names(self):
        recorder = _Recorder()
        rev = revision(recorder, PREFIX)

        await rev.push("entity://peer-b", remote_prefix="mirror/")

        target, operation, params = recorder.calls[0]
        assert (target, operation) == (REVISION_PATTERN, "push")
        assert params["type"] == "system/revision/push-params"
        assert params["data"] == {
            "prefix": PREFIX,
            "remote": "entity://peer-b",
            "remote_prefix": "mirror/",
        }

    @pytest.mark.asyncio
    async def test_pull_is_one_dispatch_not_a_client_side_orchestration(self):
        """SA-PY-6: §4 files `pull` under *SDK Orchestration (not handler
        operations)* and describes composing connect → fetch → fetch-entities →
        merge in the client. §4.2 makes it a handler operation in the
        convenience tier, and §4.4.8 puts the multi-round trie walk inside the
        peer. Re-implementing it client-side would mean issuing every
        fetch-entities round over the wire to do worse what one dispatch does.
        """
        recorder = _Recorder()
        rev = revision(recorder, PREFIX)

        await rev.pull("entity://peer-b")

        assert len(recorder.calls) == 1
        _, operation, params = recorder.calls[0]
        assert operation == "pull"
        assert params["data"]["remote"] == "entity://peer-b"

    @pytest.mark.asyncio
    async def test_fetch_redirects_the_dispatch_rather_than_naming_a_peer_param(self):
        """§4's `fetch(peer, prefix)` has no counterpart in §4.4.6's params.

        `fetch` is served by the peer holding the DAG, so "fetch from them" is
        a dispatch at their address — there is no `peer` field for the handler
        to read, and passing one would be a parameter nothing consumes.
        """
        recorder = _Recorder()
        rev = revision(recorder, PREFIX)

        await rev.fetch(peer="peer-b")

        _, operation, params = recorder.calls[0]
        assert operation == "fetch"
        assert "peer" not in params["data"]
        assert params["data"] == {"prefix": PREFIX}


# =============================================================================
# Merge config
# =============================================================================


class TestMergeConfig:
    @pytest.mark.asyncio
    async def test_lww_is_rejected_at_config_write_time(self, rev):
        """§2.3's strategy-rejection contract, enforced where it is writable.

        `lww` and `keep-both` are rejected by the operation. A `tree:put`
        straight onto the merge-config namespace bypasses that check entirely,
        which is why §4 marks the namespace handler-owned and why SDK
        capability presets must not include `put` on it.
        """
        with pytest.raises(BadRequest) as exc:
            await rev.set_merge_config(path="**/*.md", deletion_resolution="lww")
        assert exc.value.code == "invalid_strategy"

    @pytest.mark.asyncio
    async def test_a_path_scoped_config_round_trips(self, rev):
        result = await rev.set_merge_config(path="notes/*", strategy="three-way")
        assert result["status"] == "set"
        assert result["path"] == "system/revision/config/merge/path/notes/*"

        deleted = await rev.delete_merge_config(path="notes/*")
        assert deleted["status"] == "deleted"

    @pytest.mark.asyncio
    async def test_deleting_a_config_that_is_not_there_is_no_change(self, rev):
        result = await rev.delete_merge_config(type="app/note")
        assert result["status"] == "no_change"

    @pytest.mark.asyncio
    async def test_exactly_one_scope(self, rev):
        with pytest.raises(BadRequest):
            await rev.set_merge_config(strategy="three-way")
        with pytest.raises(BadRequest):
            await rev.set_merge_config(path="a", type="b", strategy="three-way")


# =============================================================================
# Prefix config
# =============================================================================


class TestPrefixConfig:
    @pytest.mark.asyncio
    async def test_a_config_write_reports_where_it_landed(self, rev):
        result = await rev.set_config("project", exclude=["ephemeral/*"])
        assert result["config_path"].endswith("/config")
        assert isinstance(result["config_hash"], bytes)

    @pytest.mark.asyncio
    async def test_enabling_auto_version_writes_the_paired_tracking_config(self, rev):
        result = await rev.set_config(
            "project",
            auto_version=True,
            exclude=[
                "system/revision/*",
                "system/tree/root/*",
                "system/tree/tracking-config/*",
                "system/history/*",
                "system/clock/*",
            ],
        )
        assert result["tracking_config_action"] == "created"
        assert result["tracking_config_path"].startswith("system/tree/tracking-config/")

    @pytest.mark.asyncio
    async def test_auto_version_without_the_required_excludes_is_refused(self, client):
        """§4.4.17 V2 — fail-closed, and only when the prefix reaches the
        engine's own paths, which is why this uses the root prefix."""
        root = client.revision("/")
        with pytest.raises(BadRequest) as exc:
            await root.set_config("everything", auto_version=True)
        assert exc.value.code == "config/missing-required-exclude"
