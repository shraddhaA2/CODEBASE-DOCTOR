import pytest
from app.pipeline.scope import classify_file_scope, normalize_scope_path


@pytest.mark.parametrize(
    "file_path,expected_scope",
    [
        # Tests scope
        ("tests/test_requests.py", "test"),
        ("tests/conftest.py", "test"),
        ("src/tests/test_sub.py", "test"),
        ("./tests/test_requests.py", "test"),
        ("test/unit/test_api.py", "test"),
        ("testing/helpers.py", "test"),
        ("unit_test.py", "test"),
        ("test_client.py", "test"),
        ("tests/testserver/server.py", "test"),

        # Source scope
        ("src/requests/api.py", "source"),
        ("requests/sessions.py", "source"),
        ("app/main.py", "source"),
        ("models.py", "source"),
        ("src/requests/__init__.py", "source"),

        # Docs scope
        ("docs/index.rst", "docs"),
        ("doc/setup.md", "docs"),
        ("documentation/guide.rst", "docs"),
        ("docs/user/quickstart.rst", "docs"),

        # Generated scope
        ("build/lib/example.py", "generated"),
        ("dist/bundle.js", "generated"),
        ("generated/schema_pb2.py", "generated"),
        ("protos/auth_pb2_grpc.py", "generated"),
        ("out/bundle.min.js", "generated"),

        # Vendor scope
        ("vendor/example.py", "vendor"),
        ("node_modules/example.js", "vendor"),
        ("third_party/lib.py", "vendor"),
        ("site-packages/pkg.py", "vendor"),
    ],
)
def test_classify_file_scope(file_path: str, expected_scope: str):
    assert classify_file_scope(file_path) == expected_scope


def test_normalize_scope_path():
    assert normalize_scope_path("./tests/test_x.py") == "tests/test_x.py"
    assert normalize_scope_path("src\\requests\\api.py") == "src/requests/api.py"
    assert normalize_scope_path("/root/file.py") == "root/file.py"
    assert normalize_scope_path("././nested/path.py") == "nested/path.py"
