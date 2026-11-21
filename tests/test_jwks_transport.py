"""The JWT key download must use trusted CAs even without system Python roots."""

import ssl
import unittest

from vibescan.session import ISSUER, JWKS


class JwksTransportTests(unittest.TestCase):
    def test_key_download_uses_a_verified_context_with_trust_anchors(self):
        # Assert the transport's trust boundary without a live network dependency.
        self.assertEqual(JWKS.uri, ISSUER + "/.well-known/jwks.json")
        context = JWKS.ssl_context
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)


if __name__ == "__main__":
    unittest.main()
