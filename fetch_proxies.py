import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup


CHANNEL_URL = "https://t.me/s/ProxyMTProto"
OUTPUT_FILE = Path("mtproto_proxies.json")

MAX_PROXIES_TO_KEEP = 3
REQUEST_TIMEOUT_SECONDS = 15
REQUEST_ATTEMPTS = 3
REQUEST_RETRY_DELAY_SECONDS = 5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class MTProtoProxy:
    server: str
    port: int
    secret: str

    @property
    def url(self) -> str:
        return f"tg://proxy?server={self.server}&port={self.port}&secret={self.secret}"

    def key(self) -> tuple[str, int, str]:
        return self.server, self.port, self.secret

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "port": self.port,
            "secret": self.secret,
            "url": self.url,
        }


def fetch_html(url: str) -> str:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    last_error: Exception | None = None

    for attempt in range(1, REQUEST_ATTEMPTS + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            if not response.text.strip():
                raise RuntimeError("Telegram returned an empty response.")

            return response.text

        except requests.RequestException as exc:
            last_error = exc
            print(
                f"Request attempt {attempt}/{REQUEST_ATTEMPTS} failed: {exc}",
                file=sys.stderr,
            )

            if attempt < REQUEST_ATTEMPTS:
                time.sleep(REQUEST_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"Failed to fetch Telegram page after {REQUEST_ATTEMPTS} attempts.") from last_error


def normalize_text(value: str) -> str:
    return (
        value.replace("\u00a0", " ")
        .replace("\u200b", "")
        .replace("\ufeff", "")
        .strip()
    )


def normalize_secret(value: str) -> str:
    return normalize_text(value).strip("`'\".,;:()[]{}<> ")


def normalize_server(value: str) -> str:
    server = normalize_text(value).strip("`'\".,;:()[]{}<> ")
    server = server.replace("https://", "").replace("http://", "")
    server = server.split("/")[0].strip()
    return server.lower()


def is_valid_server(server: str) -> bool:
    if not server:
        return False

    if server.lower() in {"unknown", "none", "null", "localhost"}:
        return False

    if len(server) > 253:
        return False

    ipv4_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    )

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(ipv4_pattern.match(server) or domain_pattern.match(server))


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def is_valid_secret(secret: str) -> bool:
    if not secret:
        return False

    if len(secret) < 16 or len(secret) > 512:
        return False

    hex_pattern = re.compile(r"^[0-9a-fA-F]+$")
    base64_urlsafe_pattern = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

    return bool(hex_pattern.match(secret) or base64_urlsafe_pattern.match(secret))


def build_proxy(server: str, port: str | int, secret: str) -> MTProtoProxy | None:
    server = normalize_server(str(server))
    secret = normalize_secret(str(secret))

    try:
        port_int = int(str(port).strip())
    except ValueError:
        return None

    if not is_valid_server(server):
        return None

    if not is_valid_port(port_int):
        return None

    if not is_valid_secret(secret):
        return None

    return MTProtoProxy(server=server, port=port_int, secret=secret)


def extract_proxy_from_tg_url(url: str) -> MTProtoProxy | None:
    decoded_url = unquote(url.strip())

    if decoded_url.startswith("tg://proxy?"):
        parsed = urlparse(decoded_url)
        query = parse_qs(parsed.query)

    elif "t.me/proxy?" in decoded_url:
        parsed = urlparse(decoded_url)
        query = parse_qs(parsed.query)

    else:
        return None

    server_values = query.get("server")
    port_values = query.get("port")
    secret_values = query.get("secret")

    if not server_values or not port_values or not secret_values:
        return None

    return build_proxy(
        server=server_values[0],
        port=port_values[0],
        secret=secret_values[0],
    )


def extract_proxy_from_text(text: str) -> MTProtoProxy | None:
    clean_text = normalize_text(text)

    server_match = re.search(
        r"(?:^|\n|\r)\s*Server\s*:\s*`?\s*([^\n\r`]+?)\s*`?\s*(?:\n|\r|$)",
        clean_text,
        flags=re.IGNORECASE,
    )

    port_match = re.search(
        r"(?:^|\n|\r)\s*Port\s*:\s*`?\s*(\d{1,5})\s*`?\s*(?:\n|\r|$)",
        clean_text,
        flags=re.IGNORECASE,
    )

    secret_match = re.search(
        r"(?:^|\n|\r)\s*Secret\s*:\s*`?\s*([A-Za-z0-9_=+\-/]+)\s*`?\s*(?:\n|\r|$)",
        clean_text,
        flags=re.IGNORECASE,
    )

    if not server_match or not port_match or not secret_match:
        return None

    return build_proxy(
        server=server_match.group(1),
        port=port_match.group(1),
        secret=secret_match.group(1),
    )


def get_message_id(message_element) -> int:
    data_post = message_element.get("data-post", "")
    match = re.search(r"/(\d+)$", data_post)

    if match:
        return int(match.group(1))

    return 0


def extract_proxies_from_message(message_element) -> list[MTProtoProxy]:
    proxies: list[MTProtoProxy] = []

    for link in message_element.select("a[href]"):
        href = link.get("href", "")
        proxy = extract_proxy_from_tg_url(href)

        if proxy is not None:
            proxies.append(proxy)

    text_element = message_element.select_one(".tgme_widget_message_text")
    if text_element is not None:
        text = text_element.get_text("\n", strip=True)
        proxy = extract_proxy_from_text(text)

        if proxy is not None:
            proxies.append(proxy)

    return proxies


def parse_proxies(html: str) -> list[MTProtoProxy]:
    soup = BeautifulSoup(html, "html.parser")

    messages = soup.select(".tgme_widget_message")
    messages = sorted(messages, key=get_message_id, reverse=True)

    proxies: list[MTProtoProxy] = []
    seen: set[tuple[str, int, str]] = set()

    for message in messages:
        for proxy in extract_proxies_from_message(message):
            key = proxy.key()

            if key in seen:
                continue

            seen.add(key)
            proxies.append(proxy)

    return proxies


def load_existing_proxies(path: Path) -> list[MTProtoProxy]:
    if not path.exists():
        return []

    try:
        raw_content = path.read_text(encoding="utf-8").strip()

        if not raw_content:
            return []

        data = json.loads(raw_content)

        if not isinstance(data, list):
            return []

        proxies: list[MTProtoProxy] = []
        seen: set[tuple[str, int, str]] = set()

        for item in data:
            if not isinstance(item, dict):
                continue

            proxy = build_proxy(
                server=item.get("server", ""),
                port=item.get("port", ""),
                secret=item.get("secret", ""),
            )

            if proxy is None:
                continue

            key = proxy.key()

            if key in seen:
                continue

            seen.add(key)
            proxies.append(proxy)

        return proxies[:MAX_PROXIES_TO_KEEP]

    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"Could not read existing {path}: {exc}. Treating it as empty.",
            file=sys.stderr,
        )
        return []


def save_proxies(path: Path, proxies: Iterable[MTProtoProxy]) -> None:
    data = [proxy.to_dict() for proxy in proxies]

    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_suffix(path.suffix + ".tmp")

    temporary_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    os.replace(temporary_path, path)


def merge_proxies(
    fetched_proxies: list[MTProtoProxy],
    existing_proxies: list[MTProtoProxy],
) -> tuple[list[MTProtoProxy], bool]:
    existing_keys = {proxy.key() for proxy in existing_proxies}

    new_proxies: list[MTProtoProxy] = []
    new_keys: set[tuple[str, int, str]] = set()

    for proxy in fetched_proxies:
        key = proxy.key()

        if key in existing_keys or key in new_keys:
            continue

        new_keys.add(key)
        new_proxies.append(proxy)

    if not new_proxies:
        return existing_proxies, False

    merged: list[MTProtoProxy] = []
    seen: set[tuple[str, int, str]] = set()

    for proxy in [*new_proxies, *existing_proxies]:
        key = proxy.key()

        if key in seen:
            continue

        seen.add(key)
        merged.append(proxy)

        if len(merged) >= MAX_PROXIES_TO_KEEP:
            break

    return merged, True


def main() -> int:
    try:
        html = fetch_html(CHANNEL_URL)
        fetched_proxies = parse_proxies(html)

        if not fetched_proxies:
            print("No valid MTProto proxies found on the Telegram preview page.", file=sys.stderr)
            return 1

        existing_proxies = load_existing_proxies(OUTPUT_FILE)

        updated_proxies, has_new_proxies = merge_proxies(
            fetched_proxies=fetched_proxies,
            existing_proxies=existing_proxies,
        )

        if not has_new_proxies:
            print("No new proxies found. mtproto_proxies.json was not changed.")
            return 0

        save_proxies(OUTPUT_FILE, updated_proxies)
        print(f"Updated {OUTPUT_FILE} with {len(updated_proxies)} proxy/proxies.")

        for index, proxy in enumerate(updated_proxies, start=1):
            print(f"{index}. {proxy.url}")

        return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())