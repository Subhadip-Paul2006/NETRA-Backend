"""Unit tests for netra_research extension module."""

from netra_research import get_research_version


def test_research_version():
    version = get_research_version()
    assert version == "0.1.0"
