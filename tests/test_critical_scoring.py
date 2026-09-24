import unittest
from api.scanner.scoring import calculate_score
from api.scanner.core import Config

class TestCriticalScoring(unittest.TestCase):
    def test_critical_score_deductions(self):
        def _score(findings):
            return calculate_score("http://test.com", findings, {}, None, False, 10, {})["score"]

        f_crit = {"severity": "Critical", "name": "Crit1", "category": "vulnerable_components"}
        f_high = {"severity": "High", "name": "High1", "category": "vulnerable_components"}
        f_med = {"severity": "Medium", "name": "Med1", "category": "vulnerable_components"}
        f_low = {"severity": "Low", "name": "Low1", "category": "vulnerable_components"}

        self.assertEqual(_score([f_crit]), 70)
        self.assertEqual(_score([f_high]), 90)
        self.assertEqual(_score([f_med]), 95)
        self.assertEqual(_score([f_low]), 98)
        self.assertEqual(_score([f_crit, f_high]), 60)
        
        # Multiple critical capped at max_penalties["Critical"] = 100
        multi_crits = [{"severity": "Critical", "name": f"Crit{i}", "category": "vulnerable_components"} for i in range(10)]
        self.assertEqual(_score(multi_crits), 0)
