import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from power_grid.core import GridAnalyzer,DNP3Analyzer

class TestGrid(unittest.TestCase):
    def test_scenario(self):
        g=GridAnalyzer()
        r=g.analyze_scenario("ukraine_2015")
        self.assertIn("225,000",r["impact"])
    def test_assess(self):
        g=GridAnalyzer()
        r=g.assess_substation({"firewall":True,"ids":True})
        self.assertIsInstance(r["score"],int)

class TestDNP3(unittest.TestCase):
    def test_parse(self):
        d=DNP3Analyzer()
        r=d.parse_request(0x0D)
        self.assertTrue(r["dangerous"])
        self.assertEqual(r["name"],"Cold Restart")

if __name__=="__main__": unittest.main()
