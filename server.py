import json
import os
import time
import urllib.error
import urllib.request

from fastmcp import FastMCP

mcp = FastMCP("Cortex XDR")

API_KEY = os.environ["CORTEX_API_KEY"]
API_KEY_ID = os.environ["CORTEX_API_KEY_ID"]
BASE_URL = os.environ["CORTEX_URL"].rstrip("/")

BASE = f"{BASE_URL}/public_api/v1"


def _auth_headers() -> dict:
    return {
        "x-xdr-auth-id": str(API_KEY_ID),
        "Authorization": API_KEY,
        "Content-Type": "application/json",
    }


def _req(path: str, body: dict) -> dict:
    url = f"{BASE}/{path}"
    data = json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method="POST", headers=_auth_headers())
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()}") from None


def _fetch_alerts(api_filters: list, search_to: int = 100) -> list[dict]:
    result = _req("alerts/get_alerts_multi_events", {
        "request_data": {
            "filters": api_filters,
            "search_from": 0,
            "search_to": search_to,
            "sort": {"field": "creation_time", "keyword": "desc"},
        }
    })
    return result.get("reply", {}).get("alerts", [])


def _shape_alert(a: dict) -> dict:
    return {
        "alert_id": a.get("alert_id"),
        "name": a.get("name"),
        "severity": a.get("severity"),
        "actor_process_image_name": a.get("actor_process_image_name"),
        "actor_process_command_line": a.get("actor_process_command_line"),
        "actor_effective_username": a.get("actor_effective_username"),
        "host_name": a.get("host_name"),
        "mitre_tactic_id_and_name": a.get("mitre_tactic_id_and_name"),
        "detection_timestamp": a.get("detection_timestamp"),
    }


def _first_from_events(events: list[dict], *keys: str):
    """Return the first non-None value for any of the given keys across all events."""
    for key in keys:
        for e in events:
            v = e.get(key)
            if v is not None:
                return v
    return None


@mcp.tool()
def get_alert(alert_id: str) -> dict:
    """Get full details for a Cortex XDR alert including actor, asset, and process info."""
    alerts = _fetch_alerts([{"field": "alert_id_list", "operator": "in", "value": [int(alert_id)]}])
    if not alerts:
        return {"error": f"Alert {alert_id} not found"}
    a = alerts[0]
    events = a.get("events") or []
    return {
        "alert_id": a.get("alert_id"),
        "name": a.get("name"),
        "description": a.get("description"),
        "severity": a.get("severity"),
        "category": a.get("category"),
        "action_pretty": a.get("action_pretty"),
        # Actor fields — prefer events array over top-level (top-level is often null)
        "actor_process_image_name": _first_from_events(events, "actor_process_image_name") or a.get("actor_process_image_name"),
        "actor_process_command_line": _first_from_events(events, "actor_process_command_line") or a.get("actor_process_command_line"),
        "actor_process_image_path": _first_from_events(events, "actor_process_image_path") or a.get("actor_process_image_path"),
        "actor_effective_username": _first_from_events(events, "actor_effective_username", "user_name") or a.get("actor_effective_username"),
        # Causality (CGO) fields — only available in events array
        "causality_actor_process_image_name": _first_from_events(events, "causality_actor_process_image_name") or a.get("causality_actor_process_image_name"),
        "causality_actor_process_command_line": _first_from_events(events, "causality_actor_process_command_line") or a.get("causality_actor_process_command_line"),
        "causality_actor_process_signature_vendor": _first_from_events(events, "causality_actor_process_signature_vendor"),
        "host_name": a.get("host_name"),
        "host_ip": a.get("host_ip"),
        "os_actor_process_image_name": _first_from_events(events, "os_actor_process_image_name") or a.get("os_actor_process_image_name"),
        "os_actor_process_command_line": _first_from_events(events, "os_actor_process_command_line") or a.get("os_actor_process_command_line"),
        "mitre_tactic_id_and_name": a.get("mitre_tactic_id_and_name"),
        "mitre_technique_id_and_name": a.get("mitre_technique_id_and_name"),
        "detection_timestamp": a.get("detection_timestamp"),
        "source": a.get("source"),
        "event_count": len(events),
    }


@mcp.tool()
def get_endpoint(hostname: str) -> dict:
    """Get endpoint details from Cortex XDR by hostname."""
    result = _req("endpoints/get_endpoints", {"request_data": {}})
    reply = result.get("reply", {})
    all_endpoints = reply if isinstance(reply, list) else reply.get("endpoints", [])
    hn = hostname.lower()
    endpoints = [e for e in all_endpoints if hn in (e.get("host_name") or "").lower()]
    if not endpoints:
        return {"error": f"Endpoint {hostname} not found"}
    e = endpoints[0]
    return {
        "endpoint_id": e.get("endpoint_id"),
        "endpoint_name": e.get("endpoint_name"),
        "endpoint_type": e.get("endpoint_type"),
        "endpoint_status": e.get("endpoint_status"),
        "os_type": e.get("os_type"),
        "os_version": e.get("os_version"),
        "ip": e.get("ip"),
        "users": e.get("users"),
        "domain": e.get("domain"),
        "install_date": e.get("install_date"),
        "last_seen": e.get("last_seen"),
        "operational_status": e.get("operational_status"),
        "group_name": e.get("group_name"),
    }


@mcp.tool()
def search_alerts(
    hostname: str | None = None,
    username: str | None = None,
    severity: str | None = None,
    alert_name: str | None = None,
    days_back: int = 7,
    limit: int = 25,
) -> list[dict]:
    """Search Cortex XDR alerts by hostname, username, severity (LOW/MEDIUM/HIGH/CRITICAL), and/or alert name.
    Fetches recent alerts (default: last 7 days) and filters client-side."""
    api_filters = [{
        "field": "creation_time",
        "operator": "gte",
        "value": int((time.time() - days_back * 86400) * 1000),
    }]
    if severity:
        api_filters.append({"field": "severity", "operator": "in", "value": [severity.upper()]})

    alerts = _fetch_alerts(api_filters, search_to=100)

    if hostname:
        hn = hostname.lower()
        alerts = [a for a in alerts if hn in (a.get("host_name") or "").lower()]
    if username:
        un = username.lower()
        alerts = [a for a in alerts if un in (a.get("actor_effective_username") or "").lower()]
    if alert_name:
        an = alert_name.lower()
        alerts = [a for a in alerts if an in (a.get("name") or "").lower()]

    return [_shape_alert(a) for a in alerts[:limit]]


@mcp.tool()
def get_alerts_for_endpoint(hostname: str, days_back: int = 7, limit: int = 20) -> list[dict]:
    """Get recent Cortex XDR alerts for a given hostname."""
    return search_alerts(hostname=hostname, days_back=days_back, limit=limit)


def _xql(query: str, timeframe: dict | None = None, timeout_secs: int = 30) -> list[dict]:
    """Run an XQL query and poll until complete, returning the result rows."""
    start_resp = _req("xql/start_xql_query", {
        "request_data": {
            "query": query,
            "timeframe": timeframe or {"relativeTime": 604800000},
        }
    })
    if not isinstance(start_resp, dict):
        raise RuntimeError(f"Unexpected XQL start response type: {type(start_resp)}: {start_resp}")
    reply = start_resp.get("reply")
    # The reply is the query ID string directly
    if isinstance(reply, str):
        query_id = reply
    elif isinstance(reply, dict):
        query_id = reply.get("queryId") or reply.get("query_id")
    else:
        query_id = None
    if not query_id:
        raise RuntimeError(f"No query ID in XQL response: {start_resp}")

    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        result_resp = _req("xql/get_query_results", {
            "request_data": {"query_id": query_id, "pending_duration": 5000}
        })
        if not isinstance(result_resp, dict):
            raise RuntimeError(f"Unexpected XQL result response: {result_resp}")
        reply = result_resp.get("reply", {})
        status = reply.get("status")
        if status == "SUCCESS":
            return reply.get("results", {}).get("data", [])
        if status == "FAIL":
            raise RuntimeError(f"XQL query failed: {reply}")
        time.sleep(2)

    raise RuntimeError("XQL query timed out")


@mcp.tool()
def get_alert_process_details(alert_id: str) -> list[dict]:
    """Get the process causality chain for a Cortex XDR alert using XQL."""
    alerts = _fetch_alerts([{"field": "alert_id_list", "operator": "in", "value": [int(alert_id)]}])
    if not alerts:
        return [{"error": f"Alert {alert_id} not found"}]
    a = alerts[0]
    events = a.get("events") or []

    # Collect unique causality IDs from all events — more accurate than a time window
    causality_ids = list({
        e["actor_process_causality_id"]
        for e in events
        if e.get("actor_process_causality_id")
    })

    if causality_ids:
        id_list = ", ".join(f'"{cid}"' for cid in causality_ids)
        query = f"""
dataset = xdr_data
| filter actor_process_causality_id in ({id_list})
| fields _time, actor_process_image_name, actor_process_command_line, actor_primary_username, causality_actor_process_image_name, causality_actor_process_command_line, action_process_image_name, action_process_image_command_line
| sort asc _time
| limit 100
"""
        ts_ms = a.get("detection_timestamp", 0)
        timeframe = {"from": ts_ms - 3_600_000, "to": ts_ms + 3_600_000}
    else:
        # Fallback to time window if no causality IDs available
        host_name = a.get("host_name", "")
        ts_ms = a.get("detection_timestamp", 0)
        timeframe = {"from": ts_ms - 300_000, "to": ts_ms + 300_000}
        query = f"""
dataset = xdr_data
| filter agent_hostname = "{host_name}" and event_type = 1
| fields _time, actor_process_image_name, actor_process_command_line, actor_primary_username, causality_actor_process_image_name, causality_actor_process_command_line, action_process_image_name, action_process_image_command_line
| sort asc _time
| limit 50
"""
    return _xql(query, timeframe=timeframe)


if __name__ == "__main__":
    mcp.run()
