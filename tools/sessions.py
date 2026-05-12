# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Session history storage — DynamoDB backend."""

import os
import time
from tools.aws_session import get_client

TABLE_NAME = os.environ.get("SESSIONS_TABLE", "")
TTL_DAYS = 30


def _ddb():
    return get_client("dynamodb", region_name=os.environ.get("AWS_REGION", "ap-northeast-1"))


def _ttl():
    return int(time.time()) + TTL_DAYS * 86400


def list_sessions(user_id: str) -> list[dict]:
    """List all sessions for a user (metadata only), sorted by lastUsed desc."""
    if not TABLE_NAME:
        return []
    resp = _ddb().query(
        TableName=TABLE_NAME,
        KeyConditionExpression="userId = :uid",
        ExpressionAttributeValues={":uid": {"S": user_id}},
        ProjectionExpression="sk, title, createdAt, lastUsed",
    )
    sessions = []
    for item in resp.get("Items", []):
        sk = item["sk"]["S"]
        if not sk.endswith("#0000"):
            continue
        sessions.append({
            "sessionId": sk.rsplit("#", 1)[0],
            "title": item.get("title", {}).get("S", ""),
            "createdAt": int(item.get("createdAt", {}).get("N", "0")),
            "lastUsed": int(item.get("lastUsed", {}).get("N", "0")),
        })
    sessions.sort(key=lambda s: s["lastUsed"], reverse=True)
    return sessions[:20]


def get_session_messages(user_id: str, session_id: str) -> list[dict]:
    """Get all messages for a session."""
    if not TABLE_NAME:
        return []
    resp = _ddb().query(
        TableName=TABLE_NAME,
        KeyConditionExpression="userId = :uid AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":uid": {"S": user_id},
            ":prefix": {"S": f"{session_id}#"},
        },
    )
    messages = []
    for item in resp.get("Items", []):
        sk = item["sk"]["S"]
        if sk.endswith("#0000"):
            continue  # skip metadata item
        messages.append({
            "role": item.get("role", {}).get("S", ""),
            "content": item.get("content", {}).get("S", ""),
            "tools": _parse_tools(item.get("tools", {})),
            "ts": int(item.get("ts", {}).get("N", "0")),
        })
    messages.sort(key=lambda m: m["ts"])
    return messages


def save_message(user_id: str, session_id: str, seq: int, role: str, content: str, tools: list | None = None):
    """Save a single message. Also creates/updates metadata item on first user message."""
    if not TABLE_NAME:
        return
    now = int(time.time() * 1000)
    ddb = _ddb()

    # Write message item (SK uses timestamp for ordering)
    item = {
        "userId": {"S": user_id},
        "sk": {"S": f"{session_id}#{seq}"},
        "role": {"S": role},
        "content": {"S": content},
        "ts": {"N": str(now)},
        "ttl": {"N": str(_ttl())},
    }
    if tools:
        item["tools"] = {"L": [{"M": {"name": {"S": t.get("name", "")}, "status": {"S": t.get("status", "")}}} for t in tools]}
    ddb.put_item(TableName=TABLE_NAME, Item=item)

    # Upsert metadata item (create on first user message, always update lastUsed)
    title = content[:50] if role == "user" else None
    update_expr = "SET lastUsed = :now, #ttl = :ttl"
    attr_values = {":now": {"N": str(now)}, ":ttl": {"N": str(_ttl())}}
    attr_names = {"#ttl": "ttl"}
    if title:
        update_expr += ", title = if_not_exists(title, :title), createdAt = if_not_exists(createdAt, :now)"
        attr_values[":title"] = {"S": title}

    ddb.update_item(
        TableName=TABLE_NAME,
        Key={"userId": {"S": user_id}, "sk": {"S": f"{session_id}#0000"}},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=attr_values,
        ExpressionAttributeNames=attr_names,
    )


def delete_session(user_id: str, session_id: str):
    """Delete all items for a session."""
    if not TABLE_NAME:
        return
    ddb = _ddb()
    resp = ddb.query(
        TableName=TABLE_NAME,
        KeyConditionExpression="userId = :uid AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":uid": {"S": user_id},
            ":prefix": {"S": f"{session_id}#"},
        },
        ProjectionExpression="userId, sk",
    )
    items = resp.get("Items", [])
    if not items:
        return
    # BatchWriteItem (max 25 per batch)
    for i in range(0, len(items), 25):
        batch = items[i:i + 25]
        ddb.batch_write_item(
            RequestItems={
                TABLE_NAME: [{"DeleteRequest": {"Key": {"userId": item["userId"], "sk": item["sk"]}}} for item in batch]
            }
        )


def _parse_tools(attr: dict) -> list[dict]:
    """Parse DDB tools list attribute."""
    if "L" not in attr:
        return []
    return [{"name": t.get("M", {}).get("name", {}).get("S", ""), "status": t.get("M", {}).get("status", {}).get("S", "")} for t in attr["L"]]
