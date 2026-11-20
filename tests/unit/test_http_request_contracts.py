"""Socket-free request admission, validation and SPA dispatch contracts."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from server.api import http_server
from server.api.routes import semantic, static


class RateAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.server = object.__new__(http_server.ProtectedHTTPServer)
        self.server.rate_lock = threading.Lock()
        self.server.rate_per_minute = 2
        self.server.client_request_times = OrderedDict()
        self.clock = patch.object(http_server.time, "monotonic", return_value=100.0).start()
        self.addCleanup(patch.stopall)
        patch.object(http_server, "MAX_RATE_CLIENT_BUCKETS", 4, create=True).start()
        patch.object(http_server, "RATE_STALE_CLEANUP_BATCH", 2, create=True).start()

    def test_capacity_does_not_evict_active_counters(self):
        for client in range(4):
            self.assertTrue(self.server.admit_client(str(client), "api"))
        self.assertFalse(self.server.admit_client("overflow", "api"))
        self.assertEqual(len(self.server.client_request_times), 4)
        self.assertTrue(self.server.admit_client("0", "api"))
        self.assertFalse(self.server.admit_client("0", "api"))

    def test_inactive_keys_expire_with_bounded_cleanup_and_recover(self):
        for client in range(4):
            self.assertTrue(self.server.admit_client(str(client), "api"))
        self.clock.return_value = 160.0
        self.assertTrue(self.server.admit_client("new", "api"))
        self.assertEqual(set(self.server.client_request_times), {("2", "api"), ("3", "api"), ("new", "api")})
        self.assertTrue(self.server.admit_client("next", "api"))
        self.assertEqual(set(self.server.client_request_times), {("new", "api"), ("next", "api")})

    def test_rejections_do_not_postpone_expiry(self):
        self.assertTrue(self.server.admit_client("a", "api"))
        self.assertTrue(self.server.admit_client("a", "api"))
        self.clock.return_value = 159.0
        self.assertFalse(self.server.admit_client("a", "api"))
        self.assertTrue(self.server.admit_client("b", "api"))
        self.clock.return_value = 160.0
        self.assertTrue(self.server.admit_client("c", "api"))
        self.assertNotIn(("a", "api"), self.server.client_request_times)
        self.assertIn(("b", "api"), self.server.client_request_times)

    def test_recent_acceptance_moves_key_after_older_keys(self):
        self.server.admit_client("a", "api")
        self.server.admit_client("b", "api")
        self.clock.return_value = 130.0
        self.server.admit_client("a", "api")
        self.clock.return_value = 160.0
        self.server.admit_client("c", "api")
        self.assertNotIn(("b", "api"), self.server.client_request_times)
        self.assertEqual(self.server.client_request_times[("a", "api")], [100.0, 130.0])
        self.assertTrue(self.server.admit_client("a", "api"))
        self.assertEqual(self.server.client_request_times[("a", "api")], [130.0, 160.0])
        self.assertFalse(self.server.admit_client("a", "api"))

    def test_bucket_and_client_isolation(self):
        for _ in range(2):
            self.assertTrue(self.server.admit_client("a", "api"))
        self.assertFalse(self.server.admit_client("a", "api"))
        self.assertTrue(self.server.admit_client("a", "reports"))
        self.assertTrue(self.server.admit_client("b", "api"))

    def test_clock_is_sampled_inside_lock(self):
        self.clock.side_effect = lambda: self.assertTrue(self.server.rate_lock.locked()) or 100.0
        self.assertTrue(self.server.admit_client("a", "api"))

    def test_concurrent_requests_do_not_exceed_window_or_capacity(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            admitted = list(pool.map(lambda _: self.server.admit_client("same", "api"), range(32)))
        self.assertEqual(sum(admitted), 2)
        with ThreadPoolExecutor(max_workers=8) as pool:
            admitted = list(pool.map(lambda i: self.server.admit_client(str(i), "api"), range(32)))
        self.assertEqual(sum(admitted), 3)
        self.assertEqual(len(self.server.client_request_times), 4)

    def test_capacity_denial_returns_retry_and_releases_slot(self):
        for client in range(4):
            self.server.admit_client(str(client), "api")
        self.server.request_slots = threading.BoundedSemaphore(1)
        handler = object.__new__(http_server.RequestHandler)
        handler.server = self.server
        handler.path = "/api/example"
        handler.command = "GET"
        handler.client_address = ("overflow", 1)
        handler._send_json = Mock()
        self.assertFalse(handler._admit_request())
        handler._send_json.assert_called_once_with({"error": "rate_limit_exceeded"}, HTTPStatus.TOO_MANY_REQUESTS, headers={"Retry-After": "60"})
        self.assertTrue(self.server.request_slots.acquire(blocking=False))
        self.clock.return_value = 160.0
        self.server.request_slots.release()
        self.assertTrue(handler._admit_request())


class RequestDispatchTests(unittest.TestCase):
    def setUp(self):
        self.handler = object.__new__(http_server.RequestHandler)
        self.handler.headers = {}
        self.handler.server = SimpleNamespace(request_slots=threading.BoundedSemaphore(1))
        self.handler._admit_request = lambda: self.handler.server.request_slots.acquire(blocking=False)
        self.handler._require_secure_api_transport = lambda path: True
        self.handler._require_capability = lambda capability: True
        self.handler._send_json = Mock()
        self.handler.send_response = Mock()
        self.handler.send_header = Mock()
        self.handler.end_headers = Mock()
        self.handler._access_decision = lambda: {"platform_owner": True}
        patch.object(http_server, "auth_required", return_value=True).start()
        self.principal = patch.object(http_server, "principal_from_headers", return_value={"role": "admin"}).start()
        patch.object(http_server, "allows", return_value=True).start()
        patch.object(http_server.routes_health, "try_handle_liveness_get", return_value=False).start()
        patch.object(http_server.routes_auth, "try_handle_account_get", return_value=False).start()
        patch.object(http_server.routes_agents, "try_handle_get", return_value=False).start()
        self.logger = patch.object(http_server, "log_internal_error", return_value="safe-error-id").start()
        self.addCleanup(patch.stopall)

    def request(self, path):
        self.handler.path = path
        self.handler.do_GET()
        self.assertTrue(self.handler.server.request_slots.acquire(blocking=False))
        self.handler.server.request_slots.release()

    def test_semantic_validation_through_actual_registry_returns_400(self):
        cases = [
            ("calibration?window_hours=abc", "invalid_semantic_calibration_window"),
            ("relations?domain_id=abc&time_from=x&time_to=y&timezone=UTC", "invalid_semantic_relation_filter"),
            ("attack-coverage?unexpected=x", "sigma_attack_filter_invalid"),
            ("scenarios?event_db_id=abc", "invalid_event_db_id"),
            ("actions?event_db_id=abc", "invalid_event_db_id"),
        ]
        for suffix, error in cases:
            with self.subTest(suffix=suffix):
                self.handler._send_json.reset_mock()
                self.request("/api/v1/semantic/" + suffix)
                self.handler._send_json.assert_called_once_with({"error": error}, HTTPStatus.BAD_REQUEST)
        self.logger.assert_not_called()

    def test_unexpected_value_error_remains_private_500(self):
        with patch.object(semantic, "try_handle_get", side_effect=ValueError("private-internal-detail")):
            self.request("/api/v1/semantic/calibration")
        self.handler._send_json.assert_called_once_with({"error": "internal_server_error", "internal_error_id": "safe-error-id"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.logger.assert_called_once()

    def test_exact_and_deep_spa_redirects_preserve_encoded_query(self):
        query = "period=24h&filter=a%2Fb%26c&filter=%D1%82&next=https%3A%2F%2Fevil.test"
        for route in ("/events", "/events/", "/events/item/7", "/settings", "/settings/", "/settings/security"):
            with self.subTest(route=route):
                self.handler.send_header.reset_mock()
                path = route + "?" + query
                self.assertIn(static, http_server.ROUTE_REGISTRY.candidates("GET", route))
                self.request(path)
                self.handler.send_header.assert_called_once_with("Location", "/app" + path)
                self.assertEqual(urlsplit(self.handler.send_header.call_args.args[1]).netloc, "")
                self.assertEqual(parse_qs(urlsplit(self.handler.send_header.call_args.args[1]).query), parse_qs(query))

    def test_unrelated_paths_remain_404(self):
        for route in ("/events-other", "/settings-other", "/unknown/settings"):
            with self.subTest(route=route):
                self.handler._send_json.reset_mock()
                self.request(route)
                self.handler._send_json.assert_called_once_with({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                self.assertNotIn(static, http_server.ROUTE_REGISTRY.candidates("GET", route))

    def test_spa_redirects_still_require_authentication(self):
        self.principal.return_value = None
        for route in ("/events", "/settings/security?period=24h"):
            self.handler.send_header.reset_mock()
            self.request(route)
            name, target = self.handler.send_header.call_args.args
            self.assertEqual(name, "Location")
            self.assertEqual(urlsplit(target).path, "/login")
            self.assertEqual(parse_qs(urlsplit(target).query), {"next": [route]})


if __name__ == "__main__":
    unittest.main()
