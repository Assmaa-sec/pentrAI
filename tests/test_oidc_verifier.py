from __future__ import annotations

import time
import unittest

from joserfc import jwt
from joserfc.jwk import RSAKey


class OIDCVerifierTests(unittest.TestCase):
    def test_verifies_rs256_signature_issuer_audience_and_expiry(self):
        from control_plane.auth import OIDCVerifier

        private_key = RSAKey.generate_key(2048, auto_kid=True)
        verifier = OIDCVerifier("https://id.example", "pentrai", "https://id.example/jwks")
        verifier._jwks = {"keys": [private_key.as_dict(private=False)]}
        verifier._refresh_at = time.monotonic() + 60
        claims = {
            "iss": "https://id.example",
            "aud": "pentrai",
            "sub": "user-1",
            "exp": int(time.time()) + 60,
        }
        token = jwt.encode({"alg": "RS256", "kid": private_key.kid}, claims, private_key)
        self.assertEqual("https://id.example|user-1", verifier.verify(token))

        claims["aud"] = "another-product"
        wrong_audience = jwt.encode({"alg": "RS256", "kid": private_key.kid}, claims, private_key)
        with self.assertRaisesRegex(ValueError, "audience"):
            verifier.verify(wrong_audience)


if __name__ == "__main__":
    unittest.main()
