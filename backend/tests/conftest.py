import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("ASSAY_DATA_DIR", tempfile.mkdtemp(prefix="assay-test-"))
SAMPLES = ROOT.parent / "samples"
