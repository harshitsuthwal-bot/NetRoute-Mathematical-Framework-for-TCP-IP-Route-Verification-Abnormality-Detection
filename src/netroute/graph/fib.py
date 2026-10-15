"""
Forwarding Information Base (FIB) and Prefix Trie for LPM Lookups.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from netroute.types import ForwardingRule, IPPrefix


class _TrieNode:
    """A node in the binary Radix Trie for IP prefix routing."""
    __slots__ = ("bit", "rule", "children")

    def __init__(self, bit: int = -1):
        self.bit: int = bit
        self.rule: Optional[ForwardingRule] = None
        self.children: Dict[int, _TrieNode] = {}


class RouterFIB:
    """
    High-performance Longest Prefix Match (LPM) Radix Trie implementation
    modeling the router's Forwarding Information Base (FIB).
    """

    def __init__(self, router_id: str):
        self.router_id: str = router_id
        self.root: _TrieNode = _TrieNode()
        self._rules_count: int = 0

    def insert(self, rule: ForwardingRule) -> None:
        """Inserts a forwarding rule into the prefix trie."""
        net = rule.prefix.network
        bits = self._network_to_bits(net)

        curr = self.root
        for b in bits:
            if b not in curr.children:
                curr.children[b] = _TrieNode(b)
            curr = curr.children[b]

        # In case of duplicate prefix, tie-break by priority (lower is preferred)
        if curr.rule is None or rule.priority < curr.rule.priority:
            if curr.rule is None:
                self._rules_count += 1
            curr.rule = rule

    def match(self, destination: str | IPPrefix) -> Optional[ForwardingRule]:
        """
        Performs Longest Prefix Match (LPM) for a destination IP or prefix.
        Returns the most specific enclosing prefix rule installed in this FIB.
        """
        if isinstance(destination, IPPrefix):
            ip_obj = destination.network.network_address
        else:
            # Strip CIDR mask if present
            ip_str = destination.split("/")[0]
            ip_obj = ipaddress.ip_address(ip_str)

        bits = self._ip_to_bits(ip_obj)

        best_match: Optional[ForwardingRule] = self.root.rule
        curr = self.root

        for b in bits:
            if b not in curr.children:
                break
            curr = curr.children[b]
            if curr.rule is not None:
                best_match = curr.rule

        return best_match

    def remove(self, prefix: IPPrefix) -> bool:
        """Removes a prefix from the FIB."""
        bits = self._network_to_bits(prefix.network)
        curr = self.root
        stack: List[Tuple[_TrieNode, int]] = []

        for b in bits:
            if b not in curr.children:
                return False
            stack.append((curr, b))
            curr = curr.children[b]

        if curr.rule is None:
            return False

        curr.rule = None
        self._rules_count -= 1

        # Prune orphan leaf nodes backwards
        while stack:
            parent, b = stack.pop()
            child = parent.children[b]
            if not child.children and child.rule is None:
                del parent.children[b]
            else:
                break

        return True

    def all_rules(self) -> List[ForwardingRule]:
        """Traverses and yields all installed rules in the FIB."""
        rules: List[ForwardingRule] = []

        def _dfs(node: _TrieNode) -> None:
            if node.rule is not None:
                rules.append(node.rule)
            for child in node.children.values():
                _dfs(child)

        _dfs(self.root)
        return rules

    def __len__(self) -> int:
        return self._rules_count

    def __repr__(self) -> str:
        return f"RouterFIB({self.router_id}, entries={self._rules_count})"

    @staticmethod
    def _ip_to_bits(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> List[int]:
        total_bits = 32 if ip_obj.version == 4 else 128
        val = int(ip_obj)
        bits = []
        for i in range(total_bits - 1, -1, -1):
            bits.append((val >> i) & 1)
        return bits

    @staticmethod
    def _network_to_bits(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> List[int]:
        val = int(net.network_address)
        total_bits = 32 if net.version == 4 else 128
        prefixlen = net.prefixlen
        bits = []
        for i in range(total_bits - 1, total_bits - 1 - prefixlen, -1):
            bits.append((val >> i) & 1)
        return bits
