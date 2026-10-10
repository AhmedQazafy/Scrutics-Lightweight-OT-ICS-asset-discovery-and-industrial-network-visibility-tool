"""
Which side of a packet offers the service, decided from the evidence the packet itself carries.

Processing is packet-local: no connection table, no reassembly. The decision says which port is
credited as a listening service on the sender, whether the sender opened the exchange (with the
confidence of that evidence), and which port the sender contacted. A packet never credits its
receiver: a receiver is credited only from its own packets.

Evidence is ranked; a weaker kind never overrides a stronger one:
  1. payload: a valid Modbus exception response, which only a server sends
     (Modbus Application Protocol Specification V1.1b3, section 7);
  2. connection: the TCP flags of the packet (SYN without ACK, SYN+ACK, RST);
  3. ports: a Modbus direction derived from port 502, then the signature table with the
     lower port taken as the service when both ports are services;
  4. nothing resolves the packet: nothing is attributed.
When payload and connection evidence contradict each other, nothing is attributed and the packet
is reported as a conflict.
"""

from dataclasses import dataclass

from scrutics.classifier.protocol import port_matches_transport
from scrutics.classifier.signatures import get_signature

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

SENDER_CLIENT = "client"
SENDER_SERVER = "server"

INITIATES_MEDIUM = "MEDIUM"
INITIATES_LOW = "LOW"

# Basis labels: which evidence decided the packet
BASIS_PAYLOAD = "payload"
BASIS_CONFLICT = "payload/connection conflict"
BASIS_RST = "tcp rst"
BASIS_SYN = "tcp syn"
BASIS_SYN_ACK = "tcp syn+ack"
BASIS_EQUAL_PORTS = "equal ports"
BASIS_PARSER_PORT = "parser port direction"
BASIS_SOURCE_PORT = "source port"
BASIS_DESTINATION_PORT = "destination port"
BASIS_TIE_BREAK = "lower port"
BASIS_NONE = "no evidence"
BASIS_FLOW = "flow record"
BASIS_ZEEK_STATE = "zeek conn_state"
BASIS_SURICATA_FLOW = "suricata flow"
BASIS_FLOW_PORTS = "flow reply, ports"
BASIS_NOT_ATTRIBUTED = "record not attributed"

# Zeek conn_state values (base/protocols/conn/main.zeek). The responder answered: the connection
# was established (S1, SF, S2, S3, RSTO) or the responder reset an established connection (RSTR).
ZEEK_RESPONDER_ANSWERED = frozenset({"S1", "SF", "S2", "S3", "RSTO", "RSTR"})
# The originator sent the opening SYN or the connection was established. Not RSTRH, SHR or OTH,
# where Zeek saw no SYN from the (purported) originator, so its direction may be a guess.
ZEEK_ORIGINATOR_OPENED = frozenset({"S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "SH"})


@dataclass(frozen=True)
class Decision:
    credit_src: int | None = None      # port credited as a listening service on the sender
    credit_dst: int | None = None      # port credited on the receiver (flow records only)
    create_dst: bool = False           # the receiver answered, so it is an asset (flow records only)
    dst_initiates: str | None = None   # the receiver opened the exchange (flow records only)
    dst_contacted: int | None = None   # service port the receiver contacted (flow records only)
    initiates: str | None = None       # confidence that the sender opened the exchange
    contacted: int | None = None       # service port the sender contacted
    sender: str | None = None          # SENDER_CLIENT, SENDER_SERVER, or None when unresolved
    conflict: bool = False
    basis: str = BASIS_NONE

    @property
    def sender_direction(self) -> str | None:
        """The packet's direction for protocol observations: "to_server", "from_server" or None."""
        if self.sender == SENDER_CLIENT:
            return "to_server"
        if self.sender == SENDER_SERVER:
            return "from_server"
        return None


def creditable(port, proto) -> bool:
    """Whether `port` can be a listening service on transport `proto`.

    The DHCP client port 68 is never a service (RFC 2131 section 4.1).
    """
    return bool(port) and port != 68 and port_matches_transport(port, proto)


def _sender_is_server(src_port, proto, basis) -> Decision:
    return Decision(credit_src=src_port if creditable(src_port, proto) else None,
                    sender=SENDER_SERVER, basis=basis)


def decide_packet(proto, src_port, dst_port, tcp_flags=None, modbus_observations=()) -> Decision:
    """Decide one packet. `tcp_flags` is the TCP flags byte, None when unknown."""
    tcp = proto == "TCP" and tcp_flags is not None
    syn = tcp and bool(tcp_flags & TCP_SYN)
    ack = tcp and bool(tcp_flags & TCP_ACK)
    rst = tcp and bool(tcp_flags & TCP_RST)

    # 1. Payload: only a server sends a Modbus exception response. With equal ports the
    # parser's direction comes from the port alone, so the payload decides nothing.
    if src_port != dst_port and any(obs.is_exception for obs in modbus_observations):
        if rst or (syn and not ack):
            return Decision(conflict=True, basis=BASIS_CONFLICT)
        return _sender_is_server(src_port, proto, BASIS_PAYLOAD)

    # 2. Connection: the TCP flags of this packet
    if rst:
        return Decision(basis=BASIS_RST)
    if syn and not ack:
        return Decision(initiates=INITIATES_MEDIUM, contacted=dst_port or None,
                        sender=SENDER_CLIENT, basis=BASIS_SYN)
    if syn and ack:
        return _sender_is_server(src_port, proto, BASIS_SYN_ACK)

    # 3. Ports. Equal ports: either peer could be the server, so the port is credited only
    # if its signature votes OT or IT, and each peer is credited from its own packets.
    if src_port and src_port == dst_port:
        sig = get_signature(src_port, proto)
        if creditable(src_port, proto) and sig is not None and sig.category in ("OT", "IT"):
            return Decision(credit_src=src_port, basis=BASIS_EQUAL_PORTS)
        return Decision(basis=BASIS_EQUAL_PORTS)

    # A validated Modbus ADU whose direction comes from port 502
    if modbus_observations:
        if modbus_observations[0].direction == "to_server":
            return Decision(initiates=INITIATES_MEDIUM, contacted=dst_port,
                            sender=SENDER_CLIENT, basis=BASIS_PARSER_PORT)
        return _sender_is_server(src_port, proto, BASIS_PARSER_PORT)

    src_service = creditable(src_port, proto)
    dst_service = creditable(dst_port, proto)
    if src_service and dst_service:
        if src_port < dst_port:
            return Decision(credit_src=src_port, sender=SENDER_SERVER, basis=BASIS_TIE_BREAK)
        return Decision(initiates=INITIATES_LOW, contacted=dst_port, sender=SENDER_CLIENT,
                        basis=BASIS_TIE_BREAK)
    if src_service:
        return Decision(credit_src=src_port, sender=SENDER_SERVER, basis=BASIS_SOURCE_PORT)
    if dst_service:
        return Decision(initiates=INITIATES_LOW, contacted=dst_port, sender=SENDER_CLIENT,
                        basis=BASIS_DESTINATION_PORT)
    return Decision(basis=BASIS_NONE)


def decide_flow_record(proto, dst_port) -> Decision:
    """A Zeek or Suricata record: the originator contacted the responder's service port."""
    return Decision(
        credit_dst=dst_port if creditable(dst_port, proto) else None,
        initiates=INITIATES_MEDIUM,
        contacted=dst_port or None,
        sender=SENDER_CLIENT,
        basis=BASIS_FLOW,
    )


def _flow_reply_by_ports(proto, orig_port, resp_port, basis) -> Decision:
    """Both sides of a UDP flow sent: the port heuristic decides which side is the service."""
    orig_service = creditable(orig_port, proto)
    resp_service = creditable(resp_port, proto)
    if orig_service and (not resp_service or orig_port < resp_port):
        return Decision(credit_src=orig_port, create_dst=True, dst_initiates=INITIATES_LOW,
                        dst_contacted=orig_port, sender=SENDER_SERVER, basis=basis)
    if resp_service:
        return Decision(credit_dst=resp_port, create_dst=True, initiates=INITIATES_LOW,
                        contacted=resp_port, sender=SENDER_CLIENT, basis=basis)
    return Decision(create_dst=True, basis=basis)


def decide_zeek_conn(proto, orig_port, resp_port, conn_state) -> Decision:
    """
    A Zeek conn.log record, from the originator's side. TCP: the responder's port is credited
    only when the state shows the responder answered, and the originator is an initiator only
    when the state shows it opened. UDP: a flow whose both sides sent (SF) is decided by the
    port heuristic; a one-way flow attributes nothing. Missing, "-" or unknown states attribute
    nothing.
    """
    if proto == "TCP":
        answered = conn_state in ZEEK_RESPONDER_ANSWERED
        opened = conn_state in ZEEK_ORIGINATOR_OPENED
        return Decision(
            credit_dst=resp_port if answered and creditable(resp_port, proto) else None,
            create_dst=answered,
            initiates=INITIATES_MEDIUM if opened else None,
            contacted=(resp_port or None) if opened else None,
            sender=SENDER_CLIENT if opened else None,
            basis=BASIS_ZEEK_STATE,
        )
    if proto == "UDP" and conn_state == "SF":
        return _flow_reply_by_ports(proto, orig_port, resp_port, BASIS_FLOW_PORTS)
    return Decision(create_dst=conn_state == "SF", basis=BASIS_NOT_ATTRIBUTED)


def decide_suricata_flow(proto, src_port, dst_port, pkts_toclient, server_tcp_flags=None) -> Decision:
    """
    A Suricata `flow` event, oriented from the flow's client. `pkts_toclient` is None when absent
    or malformed. TCP: the flow source opened; the destination's port is credited only when
    packets went to the client, unless the server's flags (`server_tcp_flags`, None when
    unknown) show a RST and no SYN: a rejected attempt, not a service. UDP: only a flow with
    packets to the client is decided, by the port heuristic.
    """
    replied = pkts_toclient is not None and pkts_toclient > 0
    if proto == "TCP":
        if (server_tcp_flags is not None and server_tcp_flags & TCP_RST
                and not server_tcp_flags & TCP_SYN):
            replied = False
        return Decision(
            credit_dst=dst_port if replied and creditable(dst_port, proto) else None,
            create_dst=replied,
            initiates=INITIATES_MEDIUM,
            contacted=dst_port or None,
            sender=SENDER_CLIENT,
            basis=BASIS_SURICATA_FLOW,
        )
    if proto == "UDP" and replied:
        return _flow_reply_by_ports(proto, src_port, dst_port, BASIS_FLOW_PORTS)
    return Decision(create_dst=replied, basis=BASIS_NOT_ATTRIBUTED)


def not_attributed() -> Decision:
    """A record whose addresses show no service or initiation (for example a Suricata alert)."""
    return Decision(basis=BASIS_NOT_ATTRIBUTED)
