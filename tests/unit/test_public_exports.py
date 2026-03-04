import waton


def test_public_exports_exist() -> None:
    for name in waton.__all__:
        assert hasattr(waton, name), name
