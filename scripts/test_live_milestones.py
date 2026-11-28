#!/usr/bin/env python3
"""The live-run milestone ladder (scripts/lift/milestones.py) and its README row.

Needs neither the game nor a compiler: the committed ladder must be well formed, a ladder (no rung held above
one that is not), and the README must hold exactly the row the ladder gives. The rules and the Direct3D comparison
are run on a small log and small records written to a temporary folder.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lift"))
import milestones  # noqa: E402

# A run log that shows every rung with a rule. The runner's lines are cut short; the game's lines (VFS, the first-frame
# banner, whose text begins with newlines, and a checksum heading) are copied from a real generated/lifted/live/last_run.txt.
LOG = ("REACHED: DLL entry returned 1 for DLL_PROCESS_ATTACH (x)\nlauncher: blocks 1\n"
       "imports called: CreateWindowExW=1 IDXGIFactory1#12=16 ID3D11Device#10=16 IDXGISwapChain#8=232\n"
       "guest: PRE_DB_APP_INIT: Done Finished VFS load_release (32006ms delta, 32041ms total, 0MB allocated total, 0 bytes delta allocated, "
       "total UniStrings:0)\n"
       "guest: \n\n*******************************************\n***  TIME TO FIRST FRAME: 161seconds\n"
       "*******************************************\n\n\nguest: - BMD checksum -----------------------------------\n")

# Record lines copied from real records in generated/lifted/d3d_watch/ (scripts/lift/watch_d3d.py's): lifted_partial.txt of a
# lifted run (lifted_menu.txt has the same lines but for PRESENT), PRESENT_COUNT and the two Buffer lines from test_1.txt and
# test_2.txt of a test program. Only the lines are real: the records the tests write are short arrangements of them.
FACTORY = "1 create Factory(pIDXGIFactory=* Mode=1 BlockedAdapters=0 PnPID= DriverVersion= EffectsPreference=h)"
ADAPTER_DESC = "1 IDXGIAdapter::GetDesc(pDesc=304 bytes) = 0"
DEVICE = ("1 create Device(pID3D11Device=* pIDXGIDevice=* pIDXGIAdapter=* CreationFlags=1 FeatureLevel=49408 FeatureSupport=15 hKMAdapter=h "
          "hUMAdapter=* UMAdapterVersion=h hKMDevice=h hUMDevice=* UMDeviceVersion=h UMDeviceFlags=16)")
CONTEXT = "1 create Context(pID3D11Device=* pID3D11DeviceContext=* ContextType=0 ContextFlags=0)"
ASSOCIATION = "1 IDXGIFactory::MakeWindowAssociation(hWnd=h Flags=6) = 0"
FULLSCREEN = "1 IDXGISwapChain::SetFullscreenState(bFullscreen=1 pTarget=*) = 887a0022"
PRESENT = "1 IDXGISwapChain::Present(SyncInterval=0 dwFlags=0) = 0"
PRESENT_COUNT = "1 IDXGISwapChain::GetLastPresentCount(pLastPresentCount=*) = 0"
BUFFER_2, BUFFER_3 = (
    f"{thread} create Buffer(pID3D11Resource=* pIDXGISurface=* pID3D11Device=* Dimension=1 Usage=0 Width=64 Height=1 Depth=1 MipLevels=1 "
    "ArraySize=1 Format=0 SampleCount=1 SampleQuality=0 BindFlags=1 CPUAccessFlags=0 MiscFlags=0 StructureByteStride=0 hKMResource=0x0 "
    "hUMResource=* UMResourceMiscFlags=0)" for thread in "23")
ADAPTER = "1 create Adapter(pIDXGIAdapter=* pIDXGIFactory=* KMTAdapterHandle=h ThunkDLLHandle=* SharedResources=true)"
TO_DEVICE = [FACTORY, ADAPTER, DEVICE, CONTEXT]
D3D_RUNGS = ("adapters", "device", "present")


class LadderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ladder = json.loads(milestones.LADDER.read_text(encoding="utf-8"))

    def test_rungs_are_the_declared_ones(self) -> None:
        self.assertEqual([(r["id"], r["title"]) for r in self.ladder["rungs"]], [(r[0], r[1]) for r in milestones.RUNGS])

    def test_it_is_a_ladder(self) -> None:
        reached = [r["reached"] for r in self.ladder["rungs"]]
        self.assertEqual(reached, sorted(reached, reverse=True), "a rung is reached above one that is not")
        for r in self.ladder["rungs"]:
            self.assertEqual(r["reached"], r["reached"] and r["evidence"] is not None, r["id"])
            self.assertFalse(r["compared"] and not r["reached"], r["id"])

    def test_a_rung_without_a_rule_is_not_reached(self) -> None:
        for (key, _, _, rule, _), r in zip(milestones.RUNGS, self.ladder["rungs"]):
            if rule is None:
                self.assertFalse(r["reached"] or r["compared"], key)

    def test_readme_row(self) -> None:
        found = milestones.ROW.search(milestones.README.read_text(encoding="utf-8"))
        self.assertIsNotNone(found, "README.md has no 'Live x64 run milestones' row")
        self.assertEqual(found.group(0), milestones.row(self.ladder))

    def test_rules(self) -> None:
        log = ("REACHED: DLL entry returned 1 for DLL_PROCESS_ATTACH (x)\nlauncher: blocks 1\n"
               "imports called: CreateWindowExW=1 IDXGIFactory1#12=2 ID3D11Device#3=0\nSTOP: here\n")
        calls = {"CreateWindowExW": 1, "IDXGIFactory1#12": 2, "ID3D11Device#3": 0}
        got = {key: rule(log, calls) for key, _, _, rule, _ in milestones.RUNGS if rule}
        self.assertTrue(got["dll_init"] and got["entry_point"] and got["adapters"] and got["window"])
        self.assertIsNone(got["vfs"])
        self.assertIsNone(got["device"], "a slot counted 0 times is not a call")
        self.assertIsNone(got["present"])
        self.assertIsNone(got["menu"])


class BuildTests(unittest.TestCase):
    """The ladder milestones.build gives for a run log and two watched records."""

    def ladder(self, log: str = LOG, original: list[str] | None = None, lifted: list[str] | None = None) -> dict[str, dict]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "generated" / "lifted" / "live").mkdir(parents=True)
        (root / "generated" / "lifted" / "live" / "last_run.txt").write_text(log, encoding="utf-8", newline="\n")
        for name, lines in (("original", original), ("lifted", lifted)):
            if lines is not None:
                (root / f"{name}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        return {r["id"]: r for r in milestones.build(root, root)["rungs"]}

    def test_menu_rule(self) -> None:
        rungs = self.ladder()
        self.assertTrue(rungs["menu"]["reached"])
        self.assertEqual(rungs["menu"]["evidence"], "***  TIME TO FIRST FRAME: 161seconds")
        self.assertFalse(rungs["menu"]["compared"])
        self.assertFalse(rungs["battle"]["reached"], "the checksum lines of a battle being loaded are not a battle running")
        self.assertFalse(self.ladder(LOG.replace(" IDXGISwapChain#8=232", ""))["menu"]["reached"], "the banner above a rung not reached")
        self.assertFalse(self.ladder(LOG.replace("***  TIME TO FIRST FRAME: 161seconds\n", ""))["menu"]["reached"])
        for joined in (LOG.replace("\n***  TIME", "***  TIME"), LOG.replace("161seconds\n", "161seconds")):  # to the asterisks above, or below
            self.assertFalse(self.ladder(joined)["menu"]["reached"], "the banner's text inside a longer line")

    def test_records_that_differ_after_the_marker(self) -> None:
        rungs = self.ladder(original=TO_DEVICE + [ASSOCIATION, PRESENT, PRESENT_COUNT, PRESENT],
                            lifted=TO_DEVICE + [ASSOCIATION, PRESENT, FULLSCREEN, PRESENT])  # a part ends at the first marker line
        self.assertEqual([rungs[key]["compared"] for key in D3D_RUNGS], [True, True, True])
        self.assertIn("before the first \"create Device(\" line: 2 lines of the lifted run against the original's 2", rungs["adapters"]["comparison"])
        self.assertIn("through the first \"create Device(\" line: 3 lines", rungs["device"]["comparison"])
        self.assertIn("through the first \"IDXGISwapChain::Present(\" line: 6 lines", rungs["present"]["comparison"])
        self.assertEqual(rungs["window"]["comparison"], "none yet")

    def test_records_that_differ_before_the_marker(self) -> None:
        rungs = self.ladder(original=TO_DEVICE + [ASSOCIATION, PRESENT], lifted=TO_DEVICE + [FULLSCREEN, FULLSCREEN, PRESENT])
        self.assertEqual([rungs[key]["compared"] for key in D3D_RUNGS], [True, True, False])
        text = rungs["present"]["comparison"]
        self.assertIn("7 lines of the lifted run against the original's 6, threads that differ: 1; thread 1 is the same for 4 calls, "
                      f"then original: {ASSOCIATION[2:]} | lifted: {FULLSCREEN[2:]}", text)
        self.assertNotIn("\n", text)

    def test_threads_are_compared_each_on_its_own(self) -> None:
        rungs = self.ladder(original=[FACTORY, BUFFER_2, BUFFER_3, DEVICE], lifted=[FACTORY, BUFFER_3, BUFFER_2, DEVICE])
        self.assertTrue(rungs["device"]["compared"], rungs["device"]["comparison"])
        rungs = self.ladder(original=[FACTORY, BUFFER_2, BUFFER_3, DEVICE], lifted=[FACTORY, BUFFER_3, DEVICE, BUFFER_2])
        self.assertFalse(rungs["device"]["compared"])
        self.assertIn(f"thread 2 is the same for 0 calls, then original: {BUFFER_2[2:]} | lifted: (no more calls)", rungs["device"]["comparison"])

    def test_a_thread_is_compared_call_by_call(self) -> None:
        for original, lifted, differs in (
                ([FACTORY, ADAPTER_DESC, DEVICE], [ADAPTER_DESC, FACTORY, DEVICE],  # the same calls in another order
                 f"thread 1 is the same for 0 calls, then original: {FACTORY[2:]} | lifted: {ADAPTER_DESC[2:]}"),
                ([FACTORY, DEVICE], [FACTORY, BUFFER_2, DEVICE],  # a thread only the lifted run has
                 f"thread 2 is the same for 0 calls, then original: (no more calls) | lifted: {BUFFER_2[2:]}"),
                ([FACTORY, BUFFER_2, BUFFER_2, DEVICE], [FACTORY, BUFFER_2, DEVICE],  # a call the lifted run does not make
                 f"thread 2 is the same for 1 calls, then original: {BUFFER_2[2:]} | lifted: (no more calls)")):
            rungs = self.ladder(original=original, lifted=lifted)
            self.assertFalse(rungs["adapters"]["compared"] or rungs["device"]["compared"], differs)
            self.assertIn(differs, rungs["device"]["comparison"])

    def test_no_adapter_before_the_device_is_not_the_enumeration(self) -> None:
        late = [FACTORY, ADAPTER_DESC, DEVICE, CONTEXT]  # as a trace begun after the adapters were made
        for records, blind in (({"original": [DEVICE, CONTEXT], "lifted": [DEVICE, CONTEXT]}, "the original game (original.txt) or of the lifted run (lifted.txt)"),
                               ({"original": late, "lifted": late}, "the original game (original.txt) or of the lifted run (lifted.txt)"),
                               ({"original": TO_DEVICE, "lifted": late}, "the lifted run (lifted.txt)")):
            rungs = self.ladder(**records)
            self.assertFalse(rungs["adapters"]["compared"], blind)
            self.assertEqual(rungs["adapters"]["comparison"],
                             f"not compared: no \"create Adapter(\" line before the first \"create Device(\" line in the watched record of {blind}")
        rungs = self.ladder(original=[DEVICE, CONTEXT], lifted=[DEVICE, CONTEXT])
        self.assertTrue(rungs["device"]["compared"])
        self.assertIn("1 lines of the lifted run against the original's 1, every thread's the same", rungs["device"]["comparison"])

    def test_a_missing_record(self) -> None:
        for records, missing in (({"original": TO_DEVICE + [PRESENT]}, "the lifted run (lifted.txt)"),
                                 ({"lifted": TO_DEVICE + [PRESENT]}, "the original game (original.txt)"),
                                 ({}, "the original game (original.txt) or of the lifted run (lifted.txt)")):
            rungs = self.ladder(**records)
            for key in D3D_RUNGS:
                self.assertFalse(rungs[key]["compared"], key)
                self.assertEqual(rungs[key]["comparison"],
                                 f"not compared: no watched record of {missing}; to record one: python scripts/lift/watch_game.py")

    def test_a_missing_marker(self) -> None:
        rungs = self.ladder(original=TO_DEVICE + [PRESENT], lifted=TO_DEVICE + [PRESENT_COUNT])
        self.assertEqual([rungs[key]["compared"] for key in D3D_RUNGS], [True, True, False])
        self.assertEqual(rungs["present"]["comparison"],
                         "not compared: no \"IDXGISwapChain::Present(\" line in the watched record of the lifted run (lifted.txt)")
        rungs = self.ladder(original=[FACTORY, ADAPTER_DESC], lifted=TO_DEVICE)
        self.assertFalse(rungs["adapters"]["compared"] or rungs["device"]["compared"])
        self.assertEqual(rungs["adapters"]["comparison"],
                         "not compared: no \"create Device(\" line in the watched record of the original game (original.txt)")

    def test_a_rung_not_reached_is_not_compared(self) -> None:
        rungs = self.ladder(LOG.replace(" IDXGISwapChain#8=232", ""), original=TO_DEVICE + [PRESENT], lifted=TO_DEVICE + [PRESENT])
        self.assertEqual([rungs[key]["compared"] for key in D3D_RUNGS], [True, True, False])
        self.assertTrue(rungs["present"]["comparison"].endswith("every thread's the same; not counted: the last run does not reach this rung"))


if __name__ == "__main__":
    unittest.main()
