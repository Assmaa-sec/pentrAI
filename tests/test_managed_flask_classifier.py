from __future__ import annotations

import shutil
import unittest
import uuid
from pathlib import Path

from static_worker.intake import FileEntry, SourceInventory
from managed_templates.classifier import classify_managed_flask


class ManagedFlaskClassifierTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(".tmp") / f"flask-classifier-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)

    def tearDown(self):
        root = self.root.resolve(strict=True)
        parent = Path(".tmp").resolve(strict=True)
        if root.parent != parent:
            raise RuntimeError("test cleanup path escaped .tmp")
        shutil.rmtree(root)

    def classify(self, files: dict[str, str]):
        entries = []
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            entries.append(FileEntry(name, path.stat().st_size, 0))
        inventory = SourceInventory("a" * 64, "b" * 64, tuple(entries), sum(item.size for item in entries))
        return classify_managed_flask(self.root, inventory)

    def test_reviewed_pinned_flask_entrypoint_matches(self):
        match = self.classify({
            "requirements.txt": "Flask==3.1.3\n",
            "wsgi.py": "from app import app\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        })
        self.assertIsNotNone(match)
        self.assertEqual("wsgi:app", match.entrypoint)
        self.assertEqual("flask-3.1.3-v1", match.template_id)

    def test_customer_dockerfile_is_static_only_even_with_valid_app(self):
        self.assertIsNone(self.classify({
            "requirements.txt": "Flask==3.1.3\n",
            "wsgi.py": "from app import app\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
            "Dockerfile": "FROM arbitrary-image\n",
        }))

    def test_extra_dependency_and_executable_wsgi_are_static_only(self):
        self.assertIsNone(self.classify({
            "requirements.txt": "Flask==3.1.3\nrequests==2.25.1\n",
            "wsgi.py": "from app import app\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        }))
        self.root.joinpath("requirements.txt").unlink()
        self.root.joinpath("wsgi.py").unlink()
        self.root.joinpath("app.py").unlink()
        self.assertIsNone(self.classify({
            "requirements.txt": "Flask==3.1.3\n",
            "wsgi.py": "from app import app\nprint('side effect')\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        }))


if __name__ == "__main__":
    unittest.main()
