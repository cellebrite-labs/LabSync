from labsync import decl_to_name_and_type


class MockTypes:
    def __getitem__(self, key: str) -> str:
        return "00000000-0000-0000-0000-000000000000"

    def get(self, key: str) -> str:
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
