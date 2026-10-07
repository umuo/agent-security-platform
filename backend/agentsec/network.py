import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import httpx


def validate_endpoint(settings, url):
    parts = urlsplit(url)
    if parts.scheme not in {"https", "http"} or not parts.hostname:
        raise ValueError("目标必须是有效的 HTTP/HTTPS URL")
    if parts.username or parts.password or parts.fragment or parts.query:
        raise ValueError("目标 URL 不允许凭据、查询参数或 fragment")
    if parts.hostname.lower() not in settings.target_hosts:
        raise ValueError("目标主机未列入 AGENTSEC_TARGET_HOSTS")
    if settings.mode == "production" and parts.scheme != "https":
        raise ValueError("生产目标必须使用 HTTPS")
    try:
        port = parts.port
    except ValueError as error:
        raise ValueError("目标端口非法") from error
    return parts, port or (443 if parts.scheme == "https" else 80)


async def bounded_request(settings, url, secret, body, timeout=30):
    """固定已登记主机，解析后绑定 IP，保持 TLS SNI；禁用代理与重定向。"""
    parts, port = validate_endpoint(settings, url)
    addresses = await asyncio.to_thread(
        socket.getaddrinfo, parts.hostname, port, 0, socket.SOCK_STREAM
    )
    if not addresses:
        raise ValueError("目标 DNS 解析失败")
    ip = str(ipaddress.ip_address(addresses[0][4][0]))
    authority = f"[{ip}]" if ":" in ip else ip
    host = parts.hostname if port in {80, 443} else f"{parts.hostname}:{port}"
    pinned = f"{parts.scheme}://{authority}:{port}{parts.path or '/'}"
    headers = {"Host": host}
    if secret:
        headers["Authorization"] = "Bearer " + secret
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
        req = client.build_request("POST", pinned, headers=headers, json=body)
        req.extensions["sni_hostname"] = parts.hostname
        response = await client.send(req, stream=True)
        try:
            if response.status_code != 200:
                raise ValueError("TARGET_HTTP_STATUS")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > 1048576:
                    raise ValueError("TARGET_RESPONSE_TOO_LARGE")
            return httpx.Response(200, content=bytes(data)).json()
        finally:
            await response.aclose()
