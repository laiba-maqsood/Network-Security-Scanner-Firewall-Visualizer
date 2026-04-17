"""
Firewall Rule Simulator - Backend Logic
Handles rule creation, priority chains, and traffic simulation.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FirewallRule:
    """Represents a single firewall rule."""
    rule_id: int
    action: str          # "ALLOW" or "DENY"
    protocol: str        # "TCP", "UDP", "ICMP", "ANY"
    src_ip: str          # source IP or "*" for any
    dst_ip: str          # destination IP or "*" for any
    port: str            # port number, range, or "*"
    priority: int        # lower number = higher priority
    description: str = ""

    def matches(self, packet: dict) -> bool:
        """Check if this rule matches a given packet."""
        # Check source IP
        if self.src_ip != "*" and self.src_ip != packet.get("src_ip", ""):
            return False

        # Check destination IP
        if self.dst_ip != "*" and self.dst_ip != packet.get("dst_ip", ""):
            return False

        # Check protocol
        if self.protocol != "ANY" and self.protocol != packet.get("protocol", "").upper():
            return False

        # Check port
        pkt_port = packet.get("port", 0)
        if self.port != "*":
            if "-" in str(self.port):
                start, end = map(int, str(self.port).split("-"))
                if not (start <= int(pkt_port) <= end):
                    return False
            else:
                if int(self.port) != int(pkt_port):
                    return False

        return True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "port": self.port,
            "priority": self.priority,
            "description": self.description,
        }


class FirewallSimulator:
    """Manages firewall rules and simulates traffic decisions."""

    def __init__(self):
        self.rules: list[FirewallRule] = []
        self._next_id = 1
        self._load_defaults()

    def _load_defaults(self):
        """Load some sensible default rules."""
        defaults = [
            ("DENY", "TCP", "*", "*", "23", 1, "Block Telnet"),
            ("DENY", "TCP", "*", "*", "445", 2, "Block SMB (ransomware risk)"),
            ("ALLOW", "TCP", "*", "*", "80", 10, "Allow HTTP"),
            ("ALLOW", "TCP", "*", "*", "443", 11, "Allow HTTPS"),
            ("ALLOW", "TCP", "*", "*", "22", 12, "Allow SSH"),
            ("DENY", "ANY", "*", "*", "*", 999, "Default Deny All"),
        ]
        for action, proto, src, dst, port, pri, desc in defaults:
            self.add_rule(action, proto, src, dst, port, pri, desc)

    def add_rule(self, action: str, protocol: str, src_ip: str,
                 dst_ip: str, port: str, priority: int, description: str = "") -> FirewallRule:
        """Add a new firewall rule."""
        rule = FirewallRule(
            rule_id=self._next_id,
            action=action.upper(),
            protocol=protocol.upper(),
            src_ip=src_ip.strip() or "*",
            dst_ip=dst_ip.strip() or "*",
            port=str(port).strip() or "*",
            priority=priority,
            description=description,
        )
        self.rules.append(rule)
        self._next_id += 1
        self._sort_rules()
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID."""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < before

    def _sort_rules(self):
        """Sort rules by priority (ascending = higher priority first)."""
        self.rules.sort(key=lambda r: r.priority)

    def evaluate_packet(self, packet: dict) -> dict:
        """
        Evaluate a packet against all rules in priority order.
        Returns decision dict with matched rule and action taken.
        """
        evaluation_log = []

        for rule in self.rules:
            matched = rule.matches(packet)
            log_entry = {
                "rule_id": rule.rule_id,
                "priority": rule.priority,
                "description": rule.description,
                "action": rule.action,
                "matched": matched,
            }
            evaluation_log.append(log_entry)

            if matched:
                return {
                    "packet": packet,
                    "decision": rule.action,
                    "matched_rule_id": rule.rule_id,
                    "matched_rule_desc": rule.description,
                    "priority": rule.priority,
                    "evaluation_log": evaluation_log,
                }

        # No rule matched — implicit deny
        return {
            "packet": packet,
            "decision": "DENY",
            "matched_rule_id": None,
            "matched_rule_desc": "Implicit default deny",
            "priority": 9999,
            "evaluation_log": evaluation_log,
        }

    def simulate_scan_results(self, scan_results: list, dst_ip: str) -> list:
        """
        Run scan results through firewall simulation.
        For each open port in scan results, simulate a packet and get decision.
        """
        simulated = []
        for result in scan_results:
            if result["state"] == "open":
                packet = {
                    "src_ip": "*",
                    "dst_ip": dst_ip,
                    "protocol": result["protocol"].upper(),
                    "port": result["port"],
                }
                decision = self.evaluate_packet(packet)
                simulated.append({
                    "port": result["port"],
                    "service": result["service"],
                    "protocol": result["protocol"].upper(),
                    "firewall_decision": decision["decision"],
                    "matched_rule": decision["matched_rule_desc"],
                    "rule_id": decision["matched_rule_id"],
                })
        return simulated

    def get_rules_as_dicts(self) -> list:
        """Return all rules as list of dicts."""
        return [r.to_dict() for r in self.rules]

    def clear_rules(self):
        """Remove all rules."""
        self.rules = []
        self._next_id = 1

    def reset_to_defaults(self):
        """Reset to default rule set."""
        self.clear_rules()
        self._load_defaults()
