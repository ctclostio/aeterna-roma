#!/usr/bin/env python3
"""Fail-closed verifier for the reproducible x64 bootstrap v2 record."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


EXPECTED_TOP_KEYS = {
    "schema_version",
    "milestone",
    "scope",
    "legacy_v1",
    "reproducible_v2",
    "build_contract",
    "toolchain",
    "inputs",
    "verification",
}
EXPECTED_V1_GATE_SHA256 = (
    "affeec3fe87e189324c08ece98a66b6e4ae4687c6e5914988ad711bd373e13c1"
)
EXPECTED_V1_DLL_SHA256 = (
    "fa4c0584790894e85a60427e0cb6adbf1266d14ddc321c122206365bdca8e3a0"
)
EXPECTED_V1_HOST_SHA256 = (
    "007b75d58e6cb6890d98b102f07fd2be353423c4f31af41f11c366679a567708"
)
EXPECTED_V2_DLL_SHA256 = (
    "ea6eabe0e510ac9593bb4aeac8ae6123dfe050ac08c9f2067115dbef9fd63930"
)
EXPECTED_V2_HOST_SHA256 = (
    "fdcdb90111cbc0cc5301bccd6f96f15566cefd9be93f9a2714c73d9c02afa320"
)
EXPECTED_V2_GATE_SHA256 = (
    "d8b2181479c2cf1f401a0569a07a4eb3524d53450526b7bb25aed7d5996112d7"
)
EXPECTED_COMPILE_OPTIONS = ["/Brepro", "/W4", "/WX", "/sdl", "/GS", "/guard:cf"]
EXPECTED_LINK_OPTIONS = [
    "/Brepro",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/HIGHENTROPYVA",
    "/NXCOMPAT",
    "/CETCOMPAT",
    "/guard:cf",
    "/WX",
]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_ARTIFACTS = {
    "dll": (
        "out/x64-bootstrap/empire.retail64.dll",
        EXPECTED_V2_DLL_SHA256,
        107520,
    ),
    "host": (
        "out/x64-bootstrap/rome2_host64.exe",
        EXPECTED_V2_HOST_SHA256,
        144384,
    ),
}
EXPECTED_MATRIX = [
    ("out/x64-bootstrap", True, False, True),
    ("out/repro-100edd70-entry-decision-verified-on", True, False, True),
    ("out/repro-100edd70-entry-decision-verified-off", False, False, True),
]
EXPECTED_CACHE_FLAG_LINES = (
    "CMAKE_C_FLAGS:STRING=/DWIN32 /D_WINDOWS",
    "CMAKE_C_FLAGS_RELEASE:STRING=/O2 /Ob2 /DNDEBUG",
    "CMAKE_EXE_LINKER_FLAGS:STRING=/machine:x64",
    "CMAKE_EXE_LINKER_FLAGS_RELEASE:STRING=/INCREMENTAL:NO",
    "CMAKE_MODULE_LINKER_FLAGS:STRING=/machine:x64",
    "CMAKE_MODULE_LINKER_FLAGS_RELEASE:STRING=/INCREMENTAL:NO",
    "CMAKE_SHARED_LINKER_FLAGS:STRING=/machine:x64",
    "CMAKE_SHARED_LINKER_FLAGS_RELEASE:STRING=/INCREMENTAL:NO",
)
EXPECTED_V2_CMAKE_TESTS = {
    "entry_policy_probe_pe_gate_unit",
    "entry_policy_probe_pe_gate",
    "entry_policy_probe_post_pe_gate",
    "startup_100f1c10_post_pe_gate",
    "startup_100f1aa0_empty_post_pe_gate",
    "startup_safe_seams_post_pe_gate",
    "startup_100df270_headless_post_pe_gate",
    "startup_100f2750_nonalloc_post_pe_gate",
    "startup_100e8240_fastpath_post_pe_gate",
    "startup_100e2460_append_prefix_post_pe_gate",
    "startup_100e2460_preallocated_branch_post_pe_gate",
    "startup_100e2460_capacity_zero_branch_post_pe_gate",
    "startup_100e2460_growth_branch_post_pe_gate",
    "startup_100e2460_router_post_pe_gate",
    "startup_100e8d00_handler_transcript_post_pe_gate",
    "startup_100e85d0_normal_adapter_post_pe_gate",
    "startup_100e8580_handler_transcript_post_pe_gate",
    "startup_100ea4d0_injected_post_pe_gate",
    "startup_100e9340_handler_transcript_post_pe_gate",
    "startup_100e92c0_handler_transcript_post_pe_gate",
    "startup_100e87a0_handler_transcript_post_pe_gate",
    "startup_100df270_suffix_transcript_post_pe_gate",
    "startup_100df270_platform_prefix_transcript_post_pe_gate",
    "startup_100ed3c0_empty_preloop_post_pe_gate",
    "startup_100ed3c0_nonempty_preloop_post_pe_gate",
    "startup_100ed3c0_nonempty_lifecycle_post_pe_gate",
    "startup_100edd70_caller_closure_post_pe_gate",
    "startup_100edd70_entry_decision_post_pe_gate",
    "startup_100ed471_ordinary_lifecycle_post_pe_gate",
}
V1_CMAKE_GATE = (
    '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate.py"'
)
V2_CMAKE_GATE = (
    '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"'
)
EXPECTED_TOOLS = {
    "cl": (
        "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe",
        "19.51.36260.0",
        "b0a1818ebae6da7f18230a84e76ce839212584ac4c2ab55b97a0d5268085da57",
        893288,
    ),
    "link": (
        "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/link.exe",
        "14.51.36260.0",
        "a8c42e25c91ca2453e1110540ac08f0fc12d7539454a11b9af8baeecb469837d",
        3701088,
    ),
    "cmake": (
        "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe",
        "4.3.1-msvc1",
        "8e30b660920a328bcc62c4b6de1b86f0de7a178aca8ec5dbb6924fd05b4eb683",
        12384816,
    ),
    "ninja": (
        "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe",
        "1.13.2",
        "4a641b1a404e390cf869b79782fecea9bc6cd9e5d2e0f97163cf4582c93bc843",
        2872880,
    ),
    "rc": (
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/rc.exe",
        "10.0.26100.8249",
        "65db0d7b4f10ba0f55973fd9356543a556da9ec1c777a0c05f05a0329c8a100a",
        55736,
    ),
    "mt": (
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/mt.exe",
        "10.0.26100.8249",
        "fb1ab75294b78619bd6ac8cadf30cb95befbc7324703cbe2654ef800ddd2bf4d",
        1972672,
    ),
}
EXPECTED_INPUTS = {
    "CMakeLists.txt": (
        "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b",
        185731,
    ),
    "port/x64_bootstrap/bootstrap_contract.h": (
        "e6e6a4a069c2d36c7e6153c4fbe69856393abb9659545551a21666346995fb3c",
        419,
    ),
    "port/x64_bootstrap/empire_bootstrap.c": (
        "5bbd9878c1b0bba2f3e7382287ddf482d507bf977cf18a646ca3ee5d8a71063f",
        1238,
    ),
    "port/x64_bootstrap/empire_bootstrap.def": (
        "7b254fc6a6909ee7b3ca20b672c6dedf40a00e93c1708b4c81bf049a0c8f3a23",
        175,
    ),
    "port/x64_bootstrap/smoke_loader.c": (
        "6cda7a4d6d915be674bbc76bcd7f716b84bf180dd6fc0ede225259968d840d7a",
        6147,
    ),
    "port/x64_bootstrap/canonical_identity.h.in": (
        "5270a640c71f8706acb5d7c36b84bdf7146764d6a4b58300e5d14e433d376063",
        439,
    ),
    "src_canonical_out/empire.retail.dll/canonical_snapshot.tsv": (
        "07962ba802e0ea39771a2ad2488b17f2be93da07d44488f3703cc6f15b49aca4",
        232,
    ),
    "generated/canonical/0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70/validation_summary.json": (
        "0cda4d0b681ae34b2147581b2c400bcd7dc844d1b7b30e932ff1fe86935375ee",
        1242,
    ),
    "generated/canonical/0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70/metadata/canonical_snapshot.tsv": (
        "07962ba802e0ea39771a2ad2488b17f2be93da07d44488f3703cc6f15b49aca4",
        232,
    ),
}


class VerificationError(RuntimeError):
    """Raised when a frozen reproducibility assertion fails."""


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                VerificationError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("manifest root must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise VerificationError(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise VerificationError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _check_pin(path: Path, sha256: Any, byte_count: Any, label: str) -> None:
    if not path.is_file():
        raise VerificationError(f"{label} is not a file: {path}")
    if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
        raise VerificationError(f"{label} has malformed SHA-256")
    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
        raise VerificationError(f"{label} has malformed byte count")
    if path.stat().st_size != byte_count:
        raise VerificationError(f"{label} byte count changed")
    if _sha256(path) != sha256:
        raise VerificationError(f"{label} SHA-256 changed")


def _repo_file(repo_root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise VerificationError(f"{label} path must be a nonempty string")
    if "\\" in relative:
        raise VerificationError(f"{label} path must use forward slashes")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise VerificationError(f"{label} path is unsafe: {relative}")
    path = (repo_root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise VerificationError(f"{label} escapes the repository") from exc
    return path


def _load_v2_gate(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("x64_probe_gate_v2_frozen", path)
    if spec is None or spec.loader is None:
        raise VerificationError("cannot create v2 gate import specification")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - diagnostic wrapper
        raise VerificationError(f"cannot import v2 gate: {exc}") from exc
    return module


def _cmake_option_body(text: str, variable: str) -> list[str]:
    match = re.search(rf"set\({re.escape(variable)}\s+(.*?)\n\)", text, re.DOTALL)
    if match is None:
        raise VerificationError(f"CMake is missing {variable}")
    options: list[str] = []
    for raw_line in match.group(1).splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            options.append(line)
    return options


def _verify_v2_cmake_routes(text: str) -> None:
    uncommented = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    if V1_CMAKE_GATE in uncommented:
        raise VerificationError("CMake still routes an active gate to v1")
    route_pattern = re.compile(
        r"add_test\(\s*NAME\s+([A-Za-z0-9_]+)\s+COMMAND\s+"
        r"Python3::Interpreter\s+-B\s+"
        + re.escape(V2_CMAKE_GATE)
        + r"(?=\s)",
        re.DOTALL,
    )
    routed_names = route_pattern.findall(uncommented)
    if uncommented.count(V2_CMAKE_GATE) != len(routed_names):
        raise VerificationError(
            "a v2 PE-gate path is not the direct command of a named CMake test"
        )
    if len(routed_names) != len(set(routed_names)):
        raise VerificationError("a named CMake test routes to v2 more than once")
    actual = set(routed_names)
    if actual != EXPECTED_V2_CMAKE_TESTS:
        raise VerificationError(
            "CMake v2 PE-gate routes differ: "
            f"missing={sorted(EXPECTED_V2_CMAKE_TESTS - actual)} "
            f"extra={sorted(actual - EXPECTED_V2_CMAKE_TESTS)}"
        )


def _verify_ninja_clean(ninja_path: Path, build_root: Path, label: str) -> None:
    try:
        completed = subprocess.run(
            [str(ninja_path), "-n", "-C", str(build_root)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(f"{label} Ninja dry-run timed out") from exc
    except OSError as exc:
        raise VerificationError(f"cannot dry-run {label}: {exc}") from exc
    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
    )
    if completed.returncode != 0:
        raise VerificationError(
            f"{label} Ninja dry-run failed ({completed.returncode}): {output}"
        )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines or lines[-1] != "ninja: no work to do.":
        preview = " | ".join(lines[-4:]) if lines else "no output"
        raise VerificationError(f"{label} Ninja graph is dirty: {preview}")


def verify(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = Path(args.manifest).resolve()
    cmake_path = Path(args.cmake).resolve()
    manifest = _read_json(manifest_path)
    _exact_keys(manifest, EXPECTED_TOP_KEYS, "manifest")
    if manifest["schema_version"] != 2:
        raise VerificationError("schema_version must equal 2")
    if manifest["milestone"] != "x64-bootstrap-reproducible-v2":
        raise VerificationError("unexpected milestone")
    if manifest["scope"] != "shipped-release-pe":
        raise VerificationError("unexpected reproducibility scope")

    legacy = _exact_keys(
        manifest["legacy_v1"],
        {
            "gate_path",
            "gate_sha256",
            "dll_sha256",
            "host_sha256",
            "dll_timestamp",
            "host_timestamp",
            "reason",
        },
        "legacy_v1",
    )
    if legacy["gate_path"] != "scripts/x64_entry_policy_probe_pe_gate.py":
        raise VerificationError("legacy gate path changed")
    if legacy["gate_sha256"] != EXPECTED_V1_GATE_SHA256:
        raise VerificationError("legacy gate pin changed")
    if legacy["dll_sha256"] != EXPECTED_V1_DLL_SHA256:
        raise VerificationError("legacy DLL pin changed")
    if legacy["host_sha256"] != EXPECTED_V1_HOST_SHA256:
        raise VerificationError("legacy host pin changed")
    if legacy["dll_timestamp"] != "0x6a8c75d6 / 2026-08-24T16:48:22Z":
        raise VerificationError("legacy DLL timestamp evidence changed")
    if legacy["host_timestamp"] != "0x6a8cecf1 / 2026-08-25T01:16:33Z":
        raise VerificationError("legacy host timestamp evidence changed")
    if legacy["reason"] != (
        "The v1 pair is code-identical to the pre-Brepro pair except for three "
        "replicated wall-clock PE timestamps per artifact; no exact v1 copy remains."
    ):
        raise VerificationError("legacy migration reason changed")
    old_gate_path = _repo_file(repo_root, legacy["gate_path"], "legacy gate")
    _check_pin(old_gate_path, legacy["gate_sha256"], 33556, "legacy gate")

    v2 = _exact_keys(
        manifest["reproducible_v2"],
        {"gate_path", "gate_sha256", "artifacts"},
        "reproducible_v2",
    )
    if v2["gate_path"] != "scripts/x64_entry_policy_probe_pe_gate_v2.py":
        raise VerificationError("v2 gate path changed")
    if v2["gate_sha256"] != EXPECTED_V2_GATE_SHA256:
        raise VerificationError("v2 gate source pin changed")
    v2_gate_path = _repo_file(repo_root, v2["gate_path"], "v2 gate")
    _check_pin(v2_gate_path, v2["gate_sha256"], 33617, "v2 gate")
    gate = _load_v2_gate(v2_gate_path)
    if gate.EXPECTED_BOOTSTRAP_DLL_SHA256 != EXPECTED_V2_DLL_SHA256:
        raise VerificationError("v2 gate DLL pin changed")
    if gate.EXPECTED_BOOTSTRAP_HOST_SHA256 != EXPECTED_V2_HOST_SHA256:
        raise VerificationError("v2 gate host pin changed")

    artifacts = v2["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise VerificationError("v2 artifacts must contain exactly DLL and host")
    by_role: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(artifacts):
        artifact = _exact_keys(
            item, {"role", "path", "sha256", "byte_count"}, f"artifact[{index}]"
        )
        role = artifact["role"]
        if role not in {"dll", "host"} or role in by_role:
            raise VerificationError("artifact roles must be unique DLL and host")
        _repo_file(repo_root, artifact["path"], f"artifact[{index}]")
        by_role[role] = artifact
    live_artifact_paths = {"dll": Path(args.dll).resolve(), "host": Path(args.host).resolve()}
    for role, (expected_path, expected_hash, expected_size) in EXPECTED_ARTIFACTS.items():
        artifact = by_role[role]
        if (
            artifact["path"] != expected_path
            or artifact["sha256"] != expected_hash
            or artifact["byte_count"] != expected_size
        ):
            raise VerificationError(f"manifest {role} pin changed")
        _check_pin(live_artifact_paths[role], expected_hash, expected_size, f"live {role}")

    contract = _exact_keys(
        manifest["build_contract"],
        {
            "generator",
            "build_type",
            "architecture",
            "testing_matrix",
            "compile_options",
            "link_options",
            "configure_recipe",
            "build_recipe",
        },
        "build_contract",
    )
    if contract["generator"] != "Ninja 1.13.2":
        raise VerificationError("generator pin changed")
    if contract["build_type"] != "Release" or contract["architecture"] != "AMD64 PE32+":
        raise VerificationError("build type or architecture pin changed")
    if contract["compile_options"] != EXPECTED_COMPILE_OPTIONS:
        raise VerificationError("compile option contract changed")
    if contract["link_options"] != EXPECTED_LINK_OPTIONS:
        raise VerificationError("link option contract changed")
    if contract["configure_recipe"] != (
        "cmake -S . -B <fresh-dir> -G Ninja -DCMAKE_BUILD_TYPE=Release "
        "-DBUILD_TESTING=<ON|OFF>"
    ):
        raise VerificationError("configure recipe changed")
    if contract["build_recipe"] != "cmake --build <fresh-dir> --config Release":
        raise VerificationError("build recipe changed")
    matrix = contract["testing_matrix"]
    if not isinstance(matrix, list) or len(matrix) != 3:
        raise VerificationError("testing matrix must record exactly three builds")
    matrix_keys = {"path", "build_testing", "external_flag_overrides", "verified_hash_pair"}
    actual_matrix: list[tuple[str, bool, bool, bool]] = []
    matrix_roots: list[tuple[str, Path]] = []
    for index, item in enumerate(matrix):
        row = _exact_keys(item, matrix_keys, f"testing_matrix[{index}]")
        matrix_root = _repo_file(
            repo_root, row["path"], f"testing_matrix[{index}]"
        )
        if not isinstance(row["build_testing"], bool) or not isinstance(
            row["external_flag_overrides"], bool
        ) or not isinstance(row["verified_hash_pair"], bool):
            raise VerificationError("testing matrix flags must be booleans")
        actual_matrix.append(
            (
                row["path"],
                row["build_testing"],
                row["external_flag_overrides"],
                row["verified_hash_pair"],
            )
        )
        if not matrix_root.is_dir():
            raise VerificationError(
                f"testing_matrix[{index}] build directory is missing"
            )
        cache_path = matrix_root / "CMakeCache.txt"
        ninja_path = matrix_root / "build.ninja"
        if not cache_path.is_file() or not ninja_path.is_file():
            raise VerificationError(
                f"testing_matrix[{index}] is not a configured Ninja build"
            )
        cache_text = cache_path.read_text(encoding="utf-8")
        expected_testing = "ON" if row["build_testing"] else "OFF"
        expected_cache_lines = (
            f"BUILD_TESTING:BOOL={expected_testing}",
            "CMAKE_BUILD_TYPE:STRING=Release",
            "CMAKE_GENERATOR:INTERNAL=Ninja",
            f"CMAKE_HOME_DIRECTORY:INTERNAL={repo_root.as_posix()}",
        ) + EXPECTED_CACHE_FLAG_LINES
        for expected_line in expected_cache_lines:
            if expected_line not in cache_text.splitlines():
                raise VerificationError(
                    f"testing_matrix[{index}] cache contract changed: "
                    f"{expected_line}"
                )
        ninja_text = ninja_path.read_text(encoding="utf-8")
        current_slice_targets = (
            "rome2_startup_100e9340_handler_transcript_runtime",
            "rome2_startup_100e9340_handler_transcript_tests",
            "rome2_startup_100e92c0_handler_transcript_runtime",
            "rome2_startup_100e92c0_handler_transcript_tests",
            "rome2_startup_100e87a0_handler_transcript_runtime",
            "rome2_startup_100e87a0_handler_transcript_tests",
            "rome2_startup_100df270_suffix_transcript_runtime",
            "rome2_startup_100df270_suffix_transcript_tests",
            "rome2_startup_100df270_platform_prefix_transcript_runtime",
            "rome2_startup_100df270_platform_prefix_transcript_tests",
            "rome2_startup_100ed3c0_empty_preloop_runtime",
            "rome2_startup_100ed3c0_empty_preloop_tests",
            "rome2_startup_100ed471_ordinary_lifecycle_runtime",
            "rome2_startup_100ed471_ordinary_lifecycle_tests",
            "rome2_startup_100ed3c0_nonempty_preloop_runtime",
            "rome2_startup_100ed3c0_nonempty_preloop_tests",
            "rome2_startup_100ed3c0_nonempty_lifecycle_runtime",
            "rome2_startup_100ed3c0_nonempty_lifecycle_tests",
            "rome2_startup_100edd70_caller_closure_runtime",
            "rome2_startup_100edd70_caller_closure_tests",
            "rome2_startup_100edd70_entry_decision_runtime",
            "rome2_startup_100edd70_entry_decision_tests",
        )
        for current_slice_target in current_slice_targets:
            if (current_slice_target in ninja_text) != row["build_testing"]:
                raise VerificationError(
                    f"testing_matrix[{index}] was not configured for the "
                    f"current slice target: {current_slice_target}"
                )
        for role, (_artifact_path, digest, byte_count) in EXPECTED_ARTIFACTS.items():
            filename = "empire.retail64.dll" if role == "dll" else "rome2_host64.exe"
            _check_pin(
                matrix_root / filename,
                digest,
                byte_count,
                f"testing_matrix[{index}] {role}",
            )
        matrix_roots.append((f"testing_matrix[{index}]", matrix_root))
    if actual_matrix != EXPECTED_MATRIX:
        raise VerificationError("testing matrix differs from the exact admitted builds")

    tools = manifest["toolchain"]
    if not isinstance(tools, list) or len(tools) != 6:
        raise VerificationError("toolchain must contain exactly six tools")
    tool_names: set[str] = set()
    for index, item in enumerate(tools):
        tool = _exact_keys(
            item, {"name", "path", "version", "sha256", "byte_count"}, f"tool[{index}]"
        )
        if tool["name"] not in EXPECTED_TOOLS or tool["name"] in tool_names:
            raise VerificationError("toolchain names are not exact and unique")
        expected_path, expected_version, expected_hash, expected_size = EXPECTED_TOOLS[tool["name"]]
        if (
            tool["path"] != expected_path
            or tool["version"] != expected_version
            or tool["sha256"] != expected_hash
            or tool["byte_count"] != expected_size
        ):
            raise VerificationError(f"tool authority changed: {tool['name']}")
        _check_pin(Path(tool["path"]), tool["sha256"], tool["byte_count"], f"tool {tool['name']}")
        tool_names.add(tool["name"])
    if tool_names != set(EXPECTED_TOOLS):
        raise VerificationError("tool authority set is incomplete")
    ninja_path = Path(EXPECTED_TOOLS["ninja"][0])
    for label, matrix_root in matrix_roots:
        _verify_ninja_clean(ninja_path, matrix_root, label)

    inputs = manifest["inputs"]
    if not isinstance(inputs, list) or len(inputs) != 9:
        raise VerificationError("inputs must contain exactly nine authorities")
    input_paths: set[str] = set()
    for index, item in enumerate(inputs):
        pin = _exact_keys(item, {"path", "sha256", "byte_count"}, f"input[{index}]")
        if pin["path"] not in EXPECTED_INPUTS or pin["path"] in input_paths:
            raise VerificationError("input paths must be unique")
        expected_hash, expected_size = EXPECTED_INPUTS[pin["path"]]
        if pin["sha256"] != expected_hash or pin["byte_count"] != expected_size:
            raise VerificationError(f"input authority changed: {pin['path']}")
        live_path = _repo_file(repo_root, pin["path"], f"input[{index}]")
        _check_pin(live_path, pin["sha256"], pin["byte_count"], f"input {pin['path']}")
        input_paths.add(pin["path"])
    if input_paths != set(EXPECTED_INPUTS):
        raise VerificationError("input authority set is incomplete")
    if cmake_path != (repo_root / "CMakeLists.txt").resolve():
        raise VerificationError("--cmake must identify the repository CMakeLists.txt")

    cmake_text = cmake_path.read_text(encoding="utf-8")
    if _cmake_option_body(cmake_text, "ROME2_HARDENED_COMPILE_OPTIONS") != EXPECTED_COMPILE_OPTIONS:
        raise VerificationError("live CMake compile options differ from the manifest")
    if _cmake_option_body(cmake_text, "ROME2_HARDENED_LINK_OPTIONS") != EXPECTED_LINK_OPTIONS:
        raise VerificationError("live CMake link options differ from the manifest")
    _verify_v2_cmake_routes(cmake_text)

    verification = _exact_keys(
        manifest["verification"],
        {
            "clean_tree_count",
            "hash_pair_equal",
            "absolute_smoke",
            "relative_smoke",
            "v2_gate_self_test",
            "v2_gate_binary",
            "pe_contract",
        },
        "verification",
    )
    if verification["clean_tree_count"] != 2:
        raise VerificationError("clean-tree evidence count changed")
    for key in (
        "hash_pair_equal",
        "absolute_smoke",
        "relative_smoke",
        "v2_gate_self_test",
        "v2_gate_binary",
    ):
        if verification[key] is not True:
            raise VerificationError(f"verification flag is not true: {key}")
    if verification["pe_contract"] != (
        "AMD64 PE32+, ASLR/high-entropy, NX, CFG table, CET compatible, /GS; "
        "unsigned as expected"
    ):
        raise VerificationError("PE contract evidence changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--dll", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cmake", required=True)
    args = parser.parse_args()
    try:
        verify(args)
    except VerificationError as exc:
        print(f"reproducible build v2 verification failed: {exc}", file=sys.stderr)
        return 1
    print("reproducible build v2 verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
