"""Check that every dependency copy is its pinned module plus the recorded patch.

Each copy is restored in a scratch directory by reversing its patch and
removing the files B-box adds. The result must have the Go module hash (h1)
that go.sum pins for that module version: upstream sing-box's go.sum for
sing-tun and sing-vmess, sum.golang.org for regexp2 and goja.
"""

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COPIES = (
    ("sing-tun", "github.com/sagernet/sing-tun", "v0.9.7-0.20261023115453-611d83b7a57b",
     "h1:GJhvtWFcBCBvvTqg1u9mL3f2yFo1kwPHglgdEjVtPEo=", "sing-tun-android-ingress.patch",
     ("redirect_ingress_discard_value_linux_test.go",)),
    ("sing-vmess", "github.com/sagernet/sing-vmess", "v0.2.9-0.20261019223527-a0c58542bd9d",
     "h1:K93710Sq6/TFl3GVs+NclQ3I+KPXFLluSsUFC0Sm0N8=", "sing-vmess-vision-pointer.patch",
     ("vless/vision_pointer_test.go", "vless/vision_pointer_utls_test.go")),
    ("regexp2", "github.com/dlclark/regexp2/v2", "v2.11.0",
     "h1:z5uRPHav+eTVpoffDSuUP2KPS4f1ONZaPDK73S8HA0w=", "regexp2-cancel.patch",
     ("bbox_context.go",)),
    ("goja", "github.com/dop251/goja", "v0.0.0-20261102223426-a177d211bf60",
     "h1:pCsZokXh1r8NmrvFz/7oQZ8plaiW2nkM7zH4m8jIpj4=", "goja-regexp-cancel.patch",
     ("bbox_regexp_interrupt.go",)),
)


def module_hash(directory, prefix):
    # Same as golang.org/x/mod/sumdb/dirhash.Hash1 over the module files.
    names = sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    for name in names:
        content = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        digest.update(f"{content}  {prefix}/{name}\n".encode())
    return "h1:" + base64.b64encode(digest.digest()).decode()


def main():
    go_mod = (ROOT.parent / "go.mod").read_text()
    failures = []
    for name, module, version, expected, patch, added in COPIES:
        with tempfile.TemporaryDirectory() as scratch:
            scratch = Path(scratch).resolve()
            copy = scratch / name
            # Copy what git tracks: a copy's own .gitignore can hide module
            # files that are present in the working tree.
            tracked = subprocess.check_output(["git", "ls-files", "-z", "--", name], cwd=ROOT, text=True)
            for path in tracked.split("\0")[:-1]:
                (scratch / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, scratch / path)
            # The ceiling keeps git from treating the scratch copy as part of
            # an enclosing repository, where it would skip outside paths.
            subprocess.run(
                ["git", "apply", "--reverse", str(ROOT / "patches" / patch)], cwd=copy, check=True,
                env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(scratch)),
            )
            for path in added:
                (copy / path).unlink()
            actual = module_hash(copy, f"{module}@{version}")
        if actual != expected:
            failures.append(f"{name}: {module}@{version} is {actual}, expected {expected}")
        if f"{module} => ./.b-box/{name}" not in go_mod:
            failures.append(f"{name}: go.mod does not replace {module} with ./.b-box/{name}")
        print(f"{name}: {module}@{version} {actual}")
    if failures:
        raise SystemExit("Dependency copies differ from their pinned modules:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
