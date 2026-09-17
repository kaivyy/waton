from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Awaitable, Callable

from waton.core.jid import jid_decode, jid_encode

if TYPE_CHECKING:
    from waton.utils.auth import StoragePort


class LIDMappingStore:
    def __init__(
        self,
        storage: StoragePort,
        usync_query_fn: Callable[[list[str]], Awaitable[dict[str, str]]] | None = None,
    ) -> None:
        self._storage = storage
        self._usync_fn = usync_query_fn
        self._cache: dict[str, str] = {}  # pn_user -> lid_user
        self._reverse_cache: dict[str, str] = {}  # lid_user -> pn_user
        self._inflight_pn_lookups: dict[str, asyncio.Future] = {}
        self._inflight_lid_lookups: dict[str, asyncio.Future] = {}

    async def load_from_storage(self) -> None:
        """Loads mapping data from storage into cache."""
        creds = await self._storage.get_creds()
        if not creds:
            return

        additional_data = creds.additional_data
        if not isinstance(additional_data, dict):
            return

        mapping_state = additional_data.get("lid_mapping")
        if not isinstance(mapping_state, dict):
            return

        pn_to_lid = mapping_state.get("pn_to_lid_user", {})
        lid_to_pn = mapping_state.get("lid_to_pn_user", {})

        self._cache.update(pn_to_lid)
        self._reverse_cache.update(lid_to_pn)

    async def save_to_storage(self) -> None:
        """Saves current cache to storage."""
        creds = await self._storage.get_creds()
        if not creds:
            return

        if creds.additional_data is None:
            creds.additional_data = {}

        mapping_state = creds.additional_data.get("lid_mapping")
        if not isinstance(mapping_state, dict):
            mapping_state = {}
            creds.additional_data["lid_mapping"] = mapping_state

        mapping_state["pn_to_lid_user"] = self._cache.copy()
        mapping_state["lid_to_pn_user"] = self._reverse_cache.copy()

        await self._storage.save_creds(creds)

    def store_lid_pn_mapping(self, lid_user: str, pn_user: str) -> None:
        """Stores a single LID to PN user mapping in memory."""
        self._cache[pn_user] = lid_user
        self._reverse_cache[lid_user] = pn_user

    def store_lid_pn_mappings(self, mappings: dict[str, str]) -> None:
        """Stores multiple LID to PN user mappings (pn_user -> lid_user)."""
        for pn_user, lid_user in mappings.items():
            self._cache[pn_user] = lid_user
            self._reverse_cache[lid_user] = pn_user

    def clear_cache(self) -> None:
        """Clears the in-memory cache."""
        self._cache.clear()
        self._reverse_cache.clear()

    def invalidate_mapping(self, user: str) -> None:
        """Invalidates a single PN or LID user entry from cache."""
        clean_user = user.split("@")[0].split(":")[0]
        if clean_user in self._cache:
            lid_val = self._cache.pop(clean_user)
            self._reverse_cache.pop(lid_val, None)
        elif clean_user in self._reverse_cache:
            pn_val = self._reverse_cache.pop(clean_user)
            self._cache.pop(pn_val, None)

    async def get_lids_for_pns(self, pn_jids: list[str]) -> dict[str, str | None]:
        """Resolves LID JIDs for a given list of PN JIDs."""
        if not pn_jids:
            return {}

        results: dict[str, str | None] = {}
        pending_users: set[str] = set()
        user_to_jids: dict[str, list[str]] = {}

        for pn_jid in pn_jids:
            decoded = jid_decode(pn_jid)
            if not decoded or decoded.server not in {"s.whatsapp.net", "hosted"}:
                results[pn_jid] = None
                continue

            pn_user = decoded.user
            user_to_jids.setdefault(pn_user, []).append(pn_jid)

            if pn_user in self._cache:
                lid_user = self._cache[pn_user]
                lid_server = "hosted.lid" if decoded.server == "hosted" else "lid"
                results[pn_jid] = jid_encode(lid_user, lid_server, decoded.device)
            else:
                pending_users.add(pn_user)

        if not pending_users:
            return results

        pending_list = sorted(list(pending_users))
        cache_key = ",".join(pending_list)

        if cache_key in self._inflight_pn_lookups:
            future = self._inflight_pn_lookups[cache_key]
            await future
        else:
            future = asyncio.Future()
            self._inflight_pn_lookups[cache_key] = future
            try:
                if self._usync_fn:
                    base_jids = [jid_encode(u, "s.whatsapp.net") for u in pending_list]
                    fetched_mappings = await self._usync_fn(base_jids)

                    new_mappings: dict[str, str] = {}
                    for pn_jid_res, lid_jid_res in fetched_mappings.items():
                        dec_pn = jid_decode(pn_jid_res)
                        dec_lid = jid_decode(lid_jid_res)
                        if dec_pn and dec_lid:
                            new_mappings[dec_pn.user] = dec_lid.user

                    if new_mappings:
                        self.store_lid_pn_mappings(new_mappings)
                        await self.save_to_storage()

                future.set_result(True)
            except Exception as e:
                future.set_exception(e)
                raise
            finally:
                self._inflight_pn_lookups.pop(cache_key, None)

        for pn_user in pending_users:
            lid_user = self._cache.get(pn_user)
            for pn_jid in user_to_jids[pn_user]:
                if lid_user:
                    decoded = jid_decode(pn_jid)
                    if decoded:
                        lid_server = "hosted.lid" if decoded.server == "hosted" else "lid"
                        results[pn_jid] = jid_encode(lid_user, lid_server, decoded.device)
                    else:
                        results[pn_jid] = None
                else:
                    results[pn_jid] = None

        return results

    async def get_lid_for_pn(self, pn_jid: str) -> str | None:
        """Resolves a single LID JID from a PN JID."""
        res = await self.get_lids_for_pns([pn_jid])
        return res.get(pn_jid)

    async def get_pns_for_lids(self, lid_jids: list[str]) -> dict[str, str | None]:
        """Resolves PN JIDs for a given list of LID JIDs."""
        if not lid_jids:
            return {}

        results: dict[str, str | None] = {}
        pending_users: set[str] = set()
        user_to_jids: dict[str, list[str]] = {}

        for lid_jid in lid_jids:
            decoded = jid_decode(lid_jid)
            if not decoded or decoded.server not in {"lid", "hosted.lid"}:
                results[lid_jid] = None
                continue

            lid_user = decoded.user
            user_to_jids.setdefault(lid_user, []).append(lid_jid)

            if lid_user in self._reverse_cache:
                pn_user = self._reverse_cache[lid_user]
                pn_server = "hosted" if decoded.server == "hosted.lid" else "s.whatsapp.net"
                results[lid_jid] = jid_encode(pn_user, pn_server, decoded.device)
            else:
                pending_users.add(lid_user)

        if not pending_users:
            return results

        pending_list = sorted(list(pending_users))
        cache_key = ",".join(pending_list)

        if cache_key in self._inflight_lid_lookups:
            future = self._inflight_lid_lookups[cache_key]
            await future
        else:
            future = asyncio.Future()
            self._inflight_lid_lookups[cache_key] = future
            try:
                future.set_result(True)
            except Exception as e:
                future.set_exception(e)
                raise
            finally:
                self._inflight_lid_lookups.pop(cache_key, None)

        for lid_user in pending_users:
            pn_user = self._reverse_cache.get(lid_user)
            for lid_jid in user_to_jids[lid_user]:
                if pn_user:
                    decoded = jid_decode(lid_jid)
                    if decoded:
                        pn_server = "hosted" if decoded.server == "hosted.lid" else "s.whatsapp.net"
                        results[lid_jid] = jid_encode(pn_user, pn_server, decoded.device)
                    else:
                        results[lid_jid] = None
                else:
                    results[lid_jid] = None

        return results

    async def get_pn_for_lid(self, lid_jid: str) -> str | None:
        """Resolves a single PN JID from a LID JID."""
        res = await self.get_pns_for_lids([lid_jid])
        return res.get(lid_jid)
