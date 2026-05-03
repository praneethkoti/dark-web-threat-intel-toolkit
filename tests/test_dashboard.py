"""
Dashboard smoke tests.

These tests verify that:
  - each page module imports without error
  - each page module exposes a callable render() function
  - dashboard/app.py parses as valid Python (without executing Streamlit)

No Streamlit server is started; no DB is required.

Run with::

    python -m pytest tests/test_dashboard.py -v
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── app.py parse test ─────────────────────────────────────────────────────────

class TestAppParsing:
    def test_app_py_is_valid_python(self):
        """dashboard/app.py must be syntactically valid Python."""
        app_path = PROJECT_ROOT / "dashboard" / "app.py"
        assert app_path.exists(), "dashboard/app.py not found"
        source = app_path.read_text(encoding="utf-8")
        # ast.parse raises SyntaxError if the file is malformed
        tree = ast.parse(source, filename=str(app_path))
        assert tree is not None

    def test_app_py_imports_each_page(self):
        """app.py must reference all six page module names."""
        app_path = PROJECT_ROOT / "dashboard" / "app.py"
        source = app_path.read_text(encoding="utf-8")
        expected_modules = [
            "overview",
            "threat_feed",
            "ioc_explorer",
            "trends",
            "report_page",
            "summarizer_page",
        ]
        for mod in expected_modules:
            assert mod in source, f"app.py does not reference page module '{mod}'"


# ── Per-page render() tests ───────────────────────────────────────────────────

# Map module path → expected callable name
_PAGES = [
    ("dashboard.pages.overview",        "render"),
    ("dashboard.pages.threat_feed",     "render"),
    ("dashboard.pages.ioc_explorer",    "render"),
    ("dashboard.pages.trends",          "render"),
    ("dashboard.pages.report_page",     "render"),
    ("dashboard.pages.summarizer_page", "render"),
]


@pytest.mark.parametrize("module_path,func_name", _PAGES)
def test_page_module_imports(module_path: str, func_name: str):
    """Each dashboard page must import cleanly."""
    # Patch streamlit before import so we don't need a running server.
    # Streamlit calls like st.set_page_config() are invoked at module load
    # in app.py but NOT in the individual page files (they only define render()).
    # This test imports page files directly, so no patching is needed.
    mod = importlib.import_module(module_path)
    assert mod is not None, f"Failed to import {module_path}"


@pytest.mark.parametrize("module_path,func_name", _PAGES)
def test_page_has_render_function(module_path: str, func_name: str):
    """Each dashboard page module must expose a callable render()."""
    mod = importlib.import_module(module_path)
    assert hasattr(mod, func_name), (
        f"{module_path} does not expose '{func_name}'"
    )
    assert callable(getattr(mod, func_name)), (
        f"{module_path}.{func_name} is not callable"
    )


# ── pages/__init__.py parse test ──────────────────────────────────────────────

class TestDashboardPackage:
    def test_dashboard_init_is_valid_python(self):
        init_path = PROJECT_ROOT / "dashboard" / "__init__.py"
        assert init_path.exists(), "dashboard/__init__.py not found"
        source = init_path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(init_path))

    def test_pages_init_is_valid_python(self):
        init_path = PROJECT_ROOT / "dashboard" / "pages" / "__init__.py"
        assert init_path.exists(), "dashboard/pages/__init__.py not found"
        source = init_path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(init_path))

    def test_all_page_files_exist(self):
        pages_dir = PROJECT_ROOT / "dashboard" / "pages"
        expected = [
            "overview.py",
            "threat_feed.py",
            "ioc_explorer.py",
            "trends.py",
            "report_page.py",
            "summarizer_page.py",
        ]
        for fname in expected:
            assert (pages_dir / fname).exists(), f"Missing page file: {fname}"
