import unittest
import ast
import glob

class CallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.implicit_calls = []
        self.invalid_calls = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'make_finding' or isinstance(node.func, ast.Name) and node.func.id == 'make_finding':
            has_conf = False
            is_literal = False
            conf_val = None
            for kw in node.keywords:
                if kw.arg == 'confidence':
                    has_conf = True
                    if isinstance(kw.value, ast.Constant):
                        is_literal = True
                        conf_val = kw.value.value
                    elif isinstance(kw.value, ast.Str):
                        is_literal = True
                        conf_val = kw.value.s
            
            if not has_conf:
                self.implicit_calls.append(node)
            elif is_literal and conf_val not in ("High", "Medium", "Low"):
                self.invalid_calls.append((node, conf_val))
                
        self.generic_visit(node)

class TestPhase2BConfidenceExplicit(unittest.TestCase):
    def test_no_implicit_confidence_in_modules(self):
        v = CallVisitor()
        files = glob.glob('api/scanner/modules/*.py') + glob.glob('api/scanner/scoring.py')
        for f in files:
            with open(f, 'r', encoding='utf-8') as fh:
                tree = ast.parse(fh.read())
            v.visit(tree)
        
        self.assertEqual(len(v.implicit_calls), 0, f"Found {len(v.implicit_calls)} implicit calls")
        self.assertEqual(len(v.invalid_calls), 0, f"Found {len(v.invalid_calls)} invalid calls")

    def test_behavioral_validation(self):
        from api.scanner.base import ScannerModule
        class DummyMod(ScannerModule):
            def run(self): pass
        mod = DummyMod()
        
        with self.assertRaises(ValueError):
            mod.make_finding("Test", "Low", "Desc", "Ev")
            
        with self.assertRaises(ValueError):
            mod.make_finding("Test", "Low", "Desc", "Ev", confidence="Invalid")
            
        f1 = mod.make_finding("Test", "Low", "Desc", "Ev", confidence="High")
        self.assertEqual(f1["confidence"], "High")
        
        f2 = mod.make_finding("Test", "Low", "Desc", "Ev", confidence="Medium")
        self.assertEqual(f2["confidence"], "Medium")

        f3 = mod.make_finding("Test", "Low", "Desc", "Ev", confidence="Low")
        self.assertEqual(f3["confidence"], "Low")