"""Power Grid Security Analysis"""
import json,hashlib
from datetime import datetime

class GridAnalyzer:
    ATTACK_SCENARIOS={
        "ukraine_2015":{"name":"Ukraine Power Grid Attack","vector":"Spear phishing -> BlackEnergy -> KillDisk",
                        "impact":"225,000 customers without power","duration":"6 hours","attribution":"Sandworm"},
        "ukraine_2016":{"name":"Industroyer/CrashOverride","vector":"Custom ICS malware targeting IEC 61850/104",
                        "impact":"Automated breaker manipulation","duration":"1 hour","attribution":"Sandworm"},
        "triton_2017":{"name":"TRITON/TRISIS","vector":"Targeted Triconex SIS controllers",
                       "impact":"Safety system compromise","duration":"Prevented","attribution":"TEMP.Veles"},
    }
    
    def analyze_scenario(self,name):
        return self.ATTACK_SCENARIOS.get(name,{"error":"Unknown scenario"})
    
    def assess_substation(self,config):
        score=100; findings=[]
        checks={"firewall":15,"ids":10,"access_control":15,"encryption":10,"monitoring":15,
                 "backup_power":10,"physical_security":10,"patch_management":10,"incident_response":5}
        for check,points in checks.items():
            if not config.get(check): score-=points; findings.append({"gap":check,"impact":points})
        return {"score":score,"rating":"SECURE" if score>=80 else "AT_RISK" if score>=50 else "CRITICAL","gaps":findings}

class DNP3Analyzer:
    FUNCTION_CODES={0x01:"Read",0x02:"Write",0x03:"Select",0x04:"Operate",0x0D:"Cold Restart",
                    0x0E:"Warm Restart",0x14:"Enable Unsolicited",0x15:"Disable Unsolicited"}
    
    def parse_request(self,function_code):
        return {"function_code":hex(function_code),"name":self.FUNCTION_CODES.get(function_code,"Unknown"),
                "dangerous":function_code in [0x02,0x04,0x0D,0x0E]}
    
    def detect_anomalies(self,traffic_log):
        anomalies=[]
        for entry in traffic_log:
            fc=entry.get("function_code",0)
            if fc in [0x0D,0x0E]: anomalies.append({**entry,"alert":"Restart command detected","severity":"CRITICAL"})
            if fc==0x04: anomalies.append({**entry,"alert":"Operate command","severity":"HIGH"})
        return anomalies

class GridHardener:
    def recommend(self):
        return ["Implement NERC CIP compliance","Deploy ICS-specific firewalls","Segment IT/OT networks",
                "Enable DNP3 Secure Authentication","Deploy substation IDS","Implement role-based access",
                "Regular penetration testing","Incident response planning","Backup communication channels"]
