# Continuous integration

The [Tests workflow](https://github.com/ctclostio/aeterna-roma/actions/workflows/ci.yml)
runs on pushes to `main`, pull requests (including forks), and manual dispatch.
It uses GitHub-hosted Windows Server 2025 / Visual Studio 2026 runners.

## Public checkout tests

- Python 3.14 and 3.15 run `python scripts/run_public_tests.py`.
  This discovers source, fixture, generator, and containment tests, plus the
  tests under `tests/`. Missing-corpus tests already marked with unittest skips
  report those skips explicitly. Original-byte `*_provenance` modules, the
  original-image return-domain module, and evidence-gate-v2 tests that read
  local canonical decompilations are identified as local-only by the runner.
- The standalone `tests/native` CMake project compiles the ported runtime and
  recovered types, then runs their CTest suites and the terminal scenario
  driver. A synthetic ESF fixture exercises campaign/VFS integration without
  retail assets. Both optimized profiles use `/W4 /WX`; assertions remain enabled.
  The `analyze` profile also runs the recovered-types `/analyze` checks.
  The second profile instruments the native code with AddressSanitizer.
- Native test results and failure logs are retained for 14 days. Game files,
  executables, canonical exports, and build-wrapper environment dumps are
  never uploaded by these workflows.

Run the same native checks from an x64 Visual Studio developer shell:

```bat
cmake -S tests/native -B out/public-native -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build out/public-native --parallel 4
ctest --test-dir out/public-native --output-on-failure --no-tests=error

cmake -S tests/native -B out/public-native-asan -G Ninja -DCMAKE_BUILD_TYPE=Release -DROME2_TYPES_ASAN=ON
cmake --build out/public-native-asan --parallel 4
ctest --test-dir out/public-native-asan --output-on-failure --no-tests=error
```

The root `CMakeLists.txt` and original-byte provenance suite retain their local
canonical-export, game-image and pinned-toolchain requirements. Public test
success does not establish whole-game equivalence or admit draft compositions
to the production bootstrap. To run all local Python checks with those inputs:

```bat
python -m unittest discover -s scripts -p "test_*.py" -t scripts
```

Source and metadata files use LF in clean checkouts so byte-level source pins
are reproducible; Windows batch files use CRLF. The public setup refreshes two
documentation pins and the normalized JSON manifest pins to their current
checked-in text, without changing original-byte function contracts.

## SonarQube Cloud

[SonarQube Cloud workflow](https://github.com/ctclostio/aeterna-roma/actions/workflows/sonarcloud.yml)
uses the existing organization `ctclostio` and project key
`ctclostio_aeterna-roma`. It analyzes maintained C code and scripts with a real
MSVC/Ninja compilation database from the standalone native build. Generated
decompilation output, game data, and scratch reports are outside the scope.
The scanner waits for the quality gate result; a rejected gate fails analysis.

Account setup (once):

1. In [SonarQube Cloud](https://sonarcloud.io/projects/create), import the GitHub
   repository `ctclostio/aeterna-roma` into organization `ctclostio` as a public
   project. Keep project key `ctclostio_aeterna-roma` and main branch `main`.
2. Select **With GitHub Actions** as the analysis method. Disable automatic
   analysis for this project to avoid conflicting analysis methods.
3. Generate a token under [My Account / Security](https://sonarcloud.io/account/security)
   with permission to analyze this project. Store it as the repository Actions
   secret `SONAR_TOKEN`; do not commit it or paste it into issues or logs.
4. Run the SonarQube Cloud workflow manually or push to `main` and verify the
   analysis at [the project dashboard](https://sonarcloud.io/dashboard?id=ctclostio_aeterna-roma).

Until the token is configured, the workflow emits an explicit setup-pending
warning and does not report that analysis has run. Fork and Dependabot pull
requests run the public tests without access to the Sonar credential.

The actions are pinned to reviewed release commit IDs. Workflow tokens have
read-only repository access, and checkout does not persist Git credentials.
