import re
import unittest
from pathlib import Path
from urllib.parse import urlparse

from scenarios.test_prompts import PROMPTS

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = REPO_ROOT / "scripts" / "c2_server.py"
ENDPOINT_PATTERN = re.compile(r'#define\s+MANAGEMENT_ENDPOINT\s+"([^"]+)"')
ROUTE_PATTERN = re.compile(r'@app\.route\("([^"]+)"')


def server_routes() -> set[str]:
    return set(ROUTE_PATTERN.findall(SERVER_PATH.read_text(encoding="utf-8")))


def scenario_endpoints() -> list[tuple[str, str]]:
    endpoints = []
    for name, data in PROMPTS.items():
        config_h = data.get("config_h")
        if not config_h:
            continue
        match = ENDPOINT_PATTERN.search(config_h)
        if match:
            endpoints.append((name, urlparse(match.group(1)).path))
    return endpoints


class C2ConsistencyTests(unittest.TestCase):
    def test_server_declares_a_route_for_every_scenario_endpoint(self):
        routes = server_routes()
        endpoints = scenario_endpoints()
        self.assertTrue(endpoints, "nenhum cenario declara MANAGEMENT_ENDPOINT")
        for name, path in endpoints:
            self.assertIn(path, routes,
                          f"cenario '{name}' aponta para {path}, que o c2_server nao atende")

    def test_collect_accepts_both_key_field_names(self):
        source = SERVER_PATH.read_text(encoding="utf-8")
        self.assertIn('payload.get("aes_key")', source)
        self.assertIn('payload.get("session_token")', source)

    def test_collect_aliases_are_registered(self):
        routes = server_routes()
        self.assertIn("/collect", routes)
        self.assertIn("/ingest", routes)


if __name__ == "__main__":
    unittest.main()
