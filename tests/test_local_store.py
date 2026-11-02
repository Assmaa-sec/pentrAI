from __future__ import annotations

import asyncio
import shutil
import unittest
import uuid
from pathlib import Path

from control_plane.local_store import LocalObjectStore


async def chunks(data: bytes):
    yield data


class LocalStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(".tmp/local-store-security") / uuid.uuid4().hex
        self.store = LocalObjectStore(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_rejects_escape_and_does_not_overwrite_existing_upload(self):
        for key in ("../outside.zip", "/absolute.zip", r"C:\outside.zip", r"a\..\outside.zip"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.store.path_for(key)
        key = "organizations/org/projects/project/uploads/grant.zip"
        asyncio.run(self.store.write_stream(key, chunks(b"first"), 5))
        with self.assertRaises(FileExistsError):
            asyncio.run(self.store.write_stream(key, chunks(b"second"), 6))
        self.assertEqual(b"first", b"".join(self.store.read_chunks(key)))


if __name__ == "__main__":
    unittest.main()
