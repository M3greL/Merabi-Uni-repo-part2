from dataclasses import dataclass
from typing import List
import csv

@dataclass
class ThreatIndicator:
    indicator: str
    indicator_type: str
    category: str
    mitre_tactic: str
    risk_score: int
    recommended_action: str


def calculate_risk_level(score: int) -> str:
    if score >= 8:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"


def print_indicator_report(indicators: List[ThreatIndicator]) -> None:
    print("=== B25 Threat Intelligence Module ===\n")

    for item in indicators:
        risk_level = calculate_risk_level(item.risk_score)

        print(f"Indicator: {item.indicator}")
        print(f"Type: {item.indicator_type}")
        print(f"Threat category: {item.category}")
        print(f"MITRE ATT&CK tactic: {item.mitre_tactic}")
        print(f"Risk score: {item.risk_score}/10")
        print(f"Risk level: {risk_level}")
        print(f"Recommended action: {item.recommended_action}")
        print("-" * 50)


def filter_high_risk(indicators: List[ThreatIndicator]) -> List[ThreatIndicator]:
    return [item for item in indicators if item.risk_score >= 8]

def export_to_csv(indicators: List[ThreatIndicator], filename: str) -> None:
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Indicator",
            "Type",
            "Category",
            "MITRE Tactic",
            "Risk Score",
            "Risk Level",
            "Recommended Action"
        ])

        for item in indicators:
            writer.writerow([
                item.indicator,
                item.indicator_type,
                item.category,
                item.mitre_tactic,
                item.risk_score,
                calculate_risk_level(item.risk_score),
                item.recommended_action
            ])

def main():
    threat_indicators = [
        ThreatIndicator(
            indicator="suspicious-login.example.com",
            indicator_type="Domain",
            category="Phishing",
            mitre_tactic="Initial Access",
            risk_score=9,
            recommended_action="Block domain and warn users not to enter credentials."
        ),
        ThreatIndicator(
            indicator="185.199.110.153",
            indicator_type="IP Address",
            category="Command and Control",
            mitre_tactic="Command and Control",
            risk_score=8,
            recommended_action="Investigate network logs and block if confirmed malicious."
        ),
        ThreatIndicator(
            indicator="44d88612fea8a8f36de82e1278abb02f",
            indicator_type="File Hash",
            category="Malware",
            mitre_tactic="Execution",
            risk_score=10,
            recommended_action="Quarantine matching files and run endpoint scan."
        ),
        ThreatIndicator(
            indicator="unknown-newsletter.example.org",
            indicator_type="Domain",
            category="Suspicious",
            mitre_tactic="Reconnaissance",
            risk_score=4,
            recommended_action="Monitor activity but do not block unless more evidence appears."
        ),
    ]

    print_indicator_report(threat_indicators)

    high_risk_items = filter_high_risk(threat_indicators)

    print("\n=== High Risk Indicators Only ===\n")
    for item in high_risk_items:
        print(f"{item.indicator} | {item.category} | Risk score: {item.risk_score}/10")


if __name__ == "__main__":
    main()