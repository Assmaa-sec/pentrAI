"""Customer model choices come only from a bounded operator-owned catalog."""

import json
import os
import unittest
from unittest.mock import patch

from control_plane.model_catalog import model_options


class ModelCatalogTests(unittest.TestCase):
    def test_multiple_model_options_and_public_fields(self):
        raw = json.dumps([{
            "id": "fast", "label": "Fast model", "provider_model": "provider-fast",
            "base_url": "https://provider.example/v1", "key_env": "PENTRAI_FAST_KEY",
            "prompt_credit_rate": 2, "completion_credit_rate": 3,
        }, {
            "id": "deep", "label": "Deep model", "provider_model": "provider-deep",
            "base_url": "https://provider.example/v1", "key_env": "PENTRAI_DEEP_KEY",
            "prompt_credit_rate": 4, "completion_credit_rate": 8,
        }])
        with patch.dict(os.environ, {"PENTRAI_MODEL_OPTIONS_JSON": raw}):
            catalog = model_options()
        self.assertEqual({"fast", "deep"}, set(catalog))
        self.assertEqual(3, catalog["fast"].completion_credit_rate)
        self.assertNotIn("key_env", catalog["fast"].public())
        self.assertNotIn("base_url", catalog["fast"].public())

    def test_rejects_customer_endpoint_or_duplicate_id(self):
        entry = {"id": "fast", "label": "Fast", "provider_model": "m",
                 "base_url": "http://internal.example/v1", "key_env": "PENTRAI_FAST_KEY",
                 "prompt_credit_rate": 1, "completion_credit_rate": 1}
        for entries in ([entry], [dict(entry, base_url="https://provider.example/v1")] * 2):
            with self.subTest(entries=entries), patch.dict(
                    os.environ, {"PENTRAI_MODEL_OPTIONS_JSON": json.dumps(entries)}):
                with self.assertRaises(ValueError):
                    model_options()
