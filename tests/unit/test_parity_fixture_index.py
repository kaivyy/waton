from tools.parity.fixture_index import load_fixture_index


def test_fixture_index_parses_domains() -> None:
    idx = load_fixture_index("tests/fixtures/parity/index.json")
    assert "messages-recv" in idx["domains"]
