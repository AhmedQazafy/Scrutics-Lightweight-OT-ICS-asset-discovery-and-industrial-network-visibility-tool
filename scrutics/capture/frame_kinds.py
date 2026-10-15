"""
Kinds of captured frames that cannot produce an asset.

Assets are built from frames that carry both a source MAC (Ethernet) and an IPv4 or ARP source
address. Other frames are counted by kind so a run that finds nothing can say what it saw. The
set of kinds is fixed (plus one "other" kind per layer), so the counter stays bounded whatever the
input. A kind describes the frame only; it does not claim why a capture produced no assets.
"""

SLL = "Linux cooked capture (SLL)"
SLL2 = "Linux cooked capture v2 (SLL2)"
RAW_IP = "raw IP without a link layer"
LLC = "IEEE 802.3 LLC (for example STP)"
OTHER_LINK = "other link type"
IPV6 = "IPv6"
OTHER_ETHERTYPE = "other ethertype"

_ETHERTYPES = {
    0x86DD: IPV6,
    0x8892: "PROFINET (0x8892)",
    0x88B8: "IEC 61850 GOOSE (0x88b8)",
    0x88BA: "IEC 61850 Sampled Values (0x88ba)",
    0x88CC: "LLDP (0x88cc)",
}

# Every kind, in the order summaries list them
KINDS = (SLL, SLL2, RAW_IP, LLC, OTHER_LINK, *_ETHERTYPES.values(), OTHER_ETHERTYPE)

_VLAN_TAGS = ("Dot1Q", "Dot1AD")


def frame_kind(pkt) -> str:
    """The kind of a frame that has no Ethernet source MAC or no IPv4/ARP source address."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Dot3, Ether

    if Ether not in pkt:
        if CookedLinux in pkt:
            return SLL
        if CookedLinuxV2 in pkt:
            return SLL2
        if Dot3 in pkt:
            return LLC
        if IP in pkt or IPv6 in pkt:
            return RAW_IP
        return OTHER_LINK
    # The ethertype of the payload: the innermost VLAN tag's type when tagged
    ethertype = pkt[Ether].type
    layer = pkt[Ether].payload
    while layer is not None and type(layer).__name__ in _VLAN_TAGS:
        ethertype = layer.type
        layer = layer.payload
    return _ETHERTYPES.get(ethertype, OTHER_ETHERTYPE)
