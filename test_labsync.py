import random
import string

import pytest

from labsync import decl_to_name_and_type, stable_topological_sort


class MockTypes:
    def __getitem__(self, key: str) -> str:
        return "00000000-0000-0000-0000-000000000000"

    @staticmethod
    def get(key: str) -> str:  # noqa: ARG004
        return "00000000-0000-0000-0000-000000000000"


def test_decl_to_name_pat() -> None:
    tests = (
        (  # normal local type
            "struct __CFString",
            "__CFString",
        ),
        (  # typedef
            "typedef const __CFString *CFStringRef;",
            "CFStringRef",
        ),
        (  # fptr typedef
            "typedef CFStringRef (__cdecl *CFArrayCopyDescriptionCallBack)(const void *);",
            "CFArrayCopyDescriptionCallBack",
        ),
        (  # forward declaration
            "struct x;",
            "x",
        ),
    )

    for t, n in tests:
        assert decl_to_name_and_type(t)[0] == n


def test_stable_topological_sort() -> None:
    tests = (
        (
            {
                "a": {"b"},
                "b": {"c"},
                "c": set(),
            },
            ("c", "b", "a"),
        ),
        (
            {
                "a": {"b"},
                "b": set(),
                "c": set(),
            },
            ("b", "a", "c"),
        ),
    )

    for graph, expected_result in tests:
        result = tuple(stable_topological_sort(graph))
        assert result == expected_result

    # test bad graphs
    with pytest.raises(ValueError):  # noqa: PT011
        tuple(stable_topological_sort({"a": "b", "b": "a"}))
    with pytest.raises(ValueError):  # noqa: PT011
        tuple(stable_topological_sort({"a": "a"}))
    with pytest.raises(ValueError):  # noqa: PT011
        tuple(stable_topological_sort({"a": "b"}))

    # test lexical ordering
    for _ in range(10):
        vertices = [random.choice(string.ascii_letters) for _ in range(10)]
        graph = {x: set() for x in vertices}
        result = tuple(stable_topological_sort(graph))
        expected_result = tuple(sorted(set(vertices)))
        assert result == expected_result
