from power_grid.core import GridAnalyzer,DNP3Analyzer
g=GridAnalyzer()
for s in ["ukraine_2015","ukraine_2016","triton_2017"]:
    info=g.analyze_scenario(s)
    print(f"{info['name']}: {info['attribution']}")
r=g.assess_substation({"firewall":True,"access_control":True,"monitoring":True})
print(f"\nSubstation: {r['rating']} ({r['score']}/100)")
