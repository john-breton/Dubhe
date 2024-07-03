import unittest
from main.ThreatInfo import ThreatInfo


class TestThreatInfo(unittest.TestCase):

    def setUp(self):
        self.threat_info = ThreatInfo()

    def test_populate_threat(self):
        threat_data = [
            "THREAT TECHNIQUE: Valid Accounts",
            "TECHNIQUE NUMBER: T1078",
            "THREAT MITIGATION: Account Use Policies",
            "MITIGATION NUMBER: M1036",
            "DETECT PATTERN: [['AcceptEventAction']]",
            "MITIGATION PATTERN: [['DecisionNode']]",
            "MITIGATION INDEX: 3"
        ]
        self.threat_info.populate_threat(threat_data)
        self.assertEqual(self.threat_info.get_technique(), "Valid Accounts")


if __name__ == '__main__':
    unittest.main()
