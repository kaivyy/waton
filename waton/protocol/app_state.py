from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, cast

from waton.utils.lt_hash import compute_lt_hash, make_lt_hash_generator


def _get_message_range(last_messages: Any) -> dict[str, Any] | None:
    if not last_messages:
        return None
    if isinstance(last_messages, dict):
        return last_messages
    if isinstance(last_messages, list) and len(last_messages) > 0:
        last_msg = last_messages[-1]
        last_ts = last_msg.get("messageTimestamp") or last_msg.get("timestamp")
        return {
            "lastMessageTimestamp": last_ts,
            "messages": last_messages,
        }
    return None


def apply_patch(state: Mapping[str, object], patch: Mapping[str, object]) -> dict[str, object]:
    raw_items = state.get("items", {})
    items: dict[str, object]
    if isinstance(raw_items, Mapping):
        typed_items = cast("Mapping[str, object]", raw_items)
        items = {str(key): value for key, value in typed_items.items()}
    else:
        items = {}

    if patch.get("op") == "set":
        key = patch.get("key")
        if isinstance(key, str):
            items[key] = patch.get("value")

    version_raw = state.get("version", 0)
    version = int(version_raw) if isinstance(version_raw, (int, float, str)) else 0
    version += 1

    if "index_mac" in patch or "indexMac" in patch or "mutations" in patch:
        generator = make_lt_hash_generator(dict(state))
        mutations = patch.get("mutations")
        if isinstance(mutations, list):
            for mut in mutations:
                if isinstance(mut, dict):
                    generator.mix(mut)
        else:
            generator.mix(dict(patch))
        res = generator.finish()
        return {
            "items": items,
            "version": version,
            "hash": res["hash"],
            "index_value_map": res["index_value_map"],
        }

    new_hash = compute_lt_hash([f"{k}:{v}".encode() for k, v in sorted(items.items())])
    return {"items": items, "version": version, "hash": new_hash}


def chat_modification_to_app_patch(mod: dict[str, Any], jid: str) -> dict[str, Any]:
    """
    Constructs an app state syncd mutation patch from a chat modification dictionary.
    Mirrors Baileys `chatModificationToAppPatch`.
    """
    if "mute" in mod:
        mute_val = mod["mute"]
        return {
            "syncAction": {
                "muteAction": {
                    "muted": bool(mute_val),
                    "muteEndTimestamp": mute_val if isinstance(mute_val, (int, float)) and mute_val > 1 else None,
                }
            },
            "index": ["mute", jid],
            "type": "regular_high",
            "apiVersion": 2,
            "operation": "set",
        }

    if "archive" in mod:
        msg_range = _get_message_range(mod.get("last_messages") or mod.get("lastMessages"))
        action: dict[str, Any] = {"archived": bool(mod["archive"])}
        if msg_range:
            action["messageRange"] = msg_range
        return {
            "syncAction": {"archiveChatAction": action},
            "index": ["archive", jid],
            "type": "regular_low",
            "apiVersion": 3,
            "operation": "set",
        }

    if "pin" in mod:
        return {
            "syncAction": {
                "pinAction": {
                    "pinned": bool(mod["pin"]),
                }
            },
            "index": ["pin_v1", jid],
            "type": "regular_low",
            "apiVersion": 5,
            "operation": "set",
        }

    if "star" in mod:
        star_info = mod["star"] if isinstance(mod["star"], dict) else {"starred": bool(mod["star"])}
        msg_id = star_info.get("message_id", mod.get("message_id", ""))
        from_me = star_info.get("from_me", mod.get("from_me", False))
        return {
            "syncAction": {
                "starAction": {
                    "starred": bool(star_info.get("starred", True)),
                }
            },
            "index": ["star", jid, str(msg_id), "1" if from_me else "0", "0"],
            "type": "regular_low",
            "apiVersion": 2,
            "operation": "set",
        }

    if "mark_read" in mod or "markRead" in mod:
        read_val = mod.get("mark_read", mod.get("markRead"))
        msg_range = _get_message_range(mod.get("last_messages") or mod.get("lastMessages"))
        action = {"read": bool(read_val)}
        if msg_range:
            action["messageRange"] = msg_range
        return {
            "syncAction": {"markChatAsReadAction": action},
            "index": ["markChatAsRead", jid],
            "type": "regular_low",
            "apiVersion": 3,
            "operation": "set",
        }

    if "delete_for_me" in mod:
        info = mod["delete_for_me"] if isinstance(mod["delete_for_me"], dict) else {}
        msg_id = info.get("message_id", mod.get("message_id", ""))
        from_me = info.get("from_me", mod.get("from_me", False))
        ts = info.get("timestamp", mod.get("timestamp", 0))
        return {
            "syncAction": {
                "deleteMessageForMeAction": {
                    "deleteMedia": bool(info.get("delete_media")),
                    "messageTimestamp": ts,
                }
            },
            "index": ["deleteMessageForMe", jid, str(msg_id), "1" if from_me else "0", "0"],
            "type": "regular_high",
            "apiVersion": 3,
            "operation": "set",
        }

    if "clear" in mod:
        msg_range = _get_message_range(mod.get("last_messages") or mod.get("lastMessages"))
        action = {}
        if msg_range:
            action["messageRange"] = msg_range
        return {
            "syncAction": {"clearChatAction": action},
            "index": ["clearChat", jid, "1", "0"],
            "type": "regular_high",
            "apiVersion": 6,
            "operation": "set",
        }

    if "delete" in mod:
        msg_range = _get_message_range(mod.get("last_messages") or mod.get("lastMessages"))
        action = {}
        if msg_range:
            action["messageRange"] = msg_range
        return {
            "syncAction": {"deleteChatAction": action},
            "index": ["deleteChat", jid, "1"],
            "type": "regular_high",
            "apiVersion": 6,
            "operation": "set",
        }

    if "contact" in mod:
        remove = bool(mod.get("remove"))
        return {
            "syncAction": {
                "contactAction": mod["contact"] or {},
            },
            "index": ["contact", jid],
            "type": "critical_unblock_low",
            "apiVersion": 2,
            "operation": "remove" if remove else "set",
        }

    if "disable_link_previews" in mod or "disableLinkPreviews" in mod:
        val = mod.get("disable_link_previews", mod.get("disableLinkPreviews"))
        return {
            "syncAction": {
                "privacySettingDisableLinkPreviewsAction": val or {}
            },
            "index": ["setting_disableLinkPreviews"],
            "type": "regular",
            "apiVersion": 8,
            "operation": "set",
        }

    if "push_name_setting" in mod or "pushNameSetting" in mod:
        name = mod.get("push_name_setting", mod.get("pushNameSetting"))
        return {
            "syncAction": {
                "pushNameSetting": {"name": str(name)}
            },
            "index": ["setting_pushName"],
            "type": "critical_block",
            "apiVersion": 1,
            "operation": "set",
        }

    if "quick_reply" in mod or "quickReply" in mod:
        qr = mod.get("quick_reply", mod.get("quickReply")) or {}
        return {
            "syncAction": {
                "quickReplyAction": {
                    "count": 0,
                    "deleted": bool(qr.get("deleted", False)),
                    "keywords": qr.get("keywords", []),
                    "message": str(qr.get("message", "")),
                    "shortcut": str(qr.get("shortcut", "")),
                }
            },
            "index": ["quick_reply", str(qr.get("timestamp", int(time.time())))],
            "type": "regular",
            "apiVersion": 2,
            "operation": "set",
        }

    if "add_label" in mod or "addLabel" in mod:
        lbl = mod.get("add_label", mod.get("addLabel")) or {}
        return {
            "syncAction": {
                "labelEditAction": {
                    "name": str(lbl.get("name", "")),
                    "color": int(lbl.get("color", 0)),
                    "predefinedId": lbl.get("predefinedId"),
                    "deleted": bool(lbl.get("deleted", False)),
                }
            },
            "index": ["label_edit", str(lbl.get("id", ""))],
            "type": "regular",
            "apiVersion": 3,
            "operation": "set",
        }

    if "add_chat_label" in mod or "addChatLabel" in mod:
        lbl = mod.get("add_chat_label", mod.get("addChatLabel")) or {}
        return {
            "syncAction": {"labelAssociationAction": {"labeled": True}},
            "index": ["label_jid", str(lbl.get("label_id", lbl.get("labelId", ""))), jid],
            "type": "regular",
            "apiVersion": 3,
            "operation": "set",
        }

    if "remove_chat_label" in mod or "removeChatLabel" in mod:
        lbl = mod.get("remove_chat_label", mod.get("removeChatLabel")) or {}
        return {
            "syncAction": {"labelAssociationAction": {"labeled": False}},
            "index": ["label_jid", str(lbl.get("label_id", lbl.get("labelId", ""))), jid],
            "type": "regular",
            "apiVersion": 3,
            "operation": "set",
        }

    if "add_message_label" in mod or "addMessageLabel" in mod:
        lbl = mod.get("add_message_label", mod.get("addMessageLabel")) or {}
        return {
            "syncAction": {"labelAssociationAction": {"labeled": True}},
            "index": [
                "label_message",
                str(lbl.get("label_id", lbl.get("labelId", ""))),
                jid,
                str(lbl.get("message_id", lbl.get("messageId", ""))),
                "0",
                "0",
            ],
            "type": "regular",
            "apiVersion": 3,
            "operation": "set",
        }

    if "remove_message_label" in mod or "removeMessageLabel" in mod:
        lbl = mod.get("remove_message_label", mod.get("removeMessageLabel")) or {}
        return {
            "syncAction": {"labelAssociationAction": {"labeled": False}},
            "index": [
                "label_message",
                str(lbl.get("label_id", lbl.get("labelId", ""))),
                jid,
                str(lbl.get("message_id", lbl.get("messageId", ""))),
                "0",
                "0",
            ],
            "type": "regular",
            "apiVersion": 3,
            "operation": "set",
        }

    raise ValueError(f"Unsupported chat modification keys: {list(mod.keys())}")


def process_contact_action(
    action: dict[str, Any],
    id_: str | None = None,
) -> list[dict[str, Any]]:
    """
    Processes a Syncd contactAction and generates contacts.upsert and lid-mapping.update events.
    Mirrors Baileys `processContactAction`.
    """
    results: list[dict[str, Any]] = []
    if not id_:
        return results

    lid_jid = action.get("lidJid")
    id_is_pn = id_.endswith("@s.whatsapp.net") or not id_.endswith("@lid")
    phone_number = id_ if id_is_pn else action.get("pnJid")

    results.append({
        "event": "contacts.upsert",
        "data": [
            {
                "id": id_,
                "name": action.get("fullName") or action.get("firstName") or action.get("username"),
                "username": action.get("username"),
                "lid": lid_jid,
                "phoneNumber": phone_number,
            }
        ],
    })

    if lid_jid and id_is_pn and (lid_jid.endswith("@lid") or "lid" in lid_jid):
        results.append({
            "event": "lid-mapping.update",
            "data": {"lid": lid_jid, "pn": id_},
        })

    return results
