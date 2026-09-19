import subprocess
import os

def test_js_mapper():
    script_path = os.path.join(os.path.dirname(__file__), 'test_phase3_js_mapper.js')
    result = subprocess.run(['node', script_path], capture_output=True, text=True)
    assert result.returncode == 0, f"JS tests failed:\n{result.stderr}\n{result.stdout}"
