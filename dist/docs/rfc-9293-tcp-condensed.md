# RFC 9293 - TCP Implementation Reference

Condensed from RFC 9293 (August 2022, obsoletes RFC 793).
Organized as an implementation guide for a fully compliant TCP stack.

---

## 1. Header Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    [Options + Padding]                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Details

| Field | Bits | Description |
|-------|------|-------------|
| Source Port | 16 | Sender's port |
| Destination Port | 16 | Receiver's port |
| Sequence Number | 32 | First data octet seq (or ISN if SYN set; first data octet is ISN+1) |
| Acknowledgment Number | 32 | Next seq expected (valid when ACK set; ACK is always set once connection established) |
| Data Offset | 4 | Header length in 32-bit words (min 5, max 15) |
| Reserved | 4 | Must be zero on send, ignored on receive |
| CWR | 1 | Congestion Window Reduced (RFC 3168) |
| ECE | 1 | ECN-Echo (RFC 3168) |
| URG | 1 | Urgent pointer is significant |
| ACK | 1 | Acknowledgment field is significant |
| PSH | 1 | Push data to receiver application |
| RST | 1 | Reset the connection |
| SYN | 1 | Synchronize sequence numbers |
| FIN | 1 | No more data from sender |
| Window | 16 | Receive window size in octets (MUST treat as unsigned, MUST-1). RECOMMENDED to use 32-bit fields internally (REC-1). |
| Checksum | 16 | Ones' complement checksum over pseudo-header + header + data |
| Urgent Pointer | 16 | Offset from SEQ to octet AFTER urgent data (when URG set) |

### Checksum Pseudo-Headers

**IPv4 pseudo-header (96 bits):**
- Source Address (32), Destination Address (32), zero (8), Protocol=6 (8), TCP Length (16)

**IPv6 pseudo-header (320 bits):**
- Source Address (128), Destination Address (128), Upper-Layer Packet Length (32), zero (24), Next Header=6 (8)

**Computation details:**
- Sum all 16-bit words of pseudo-header + TCP header + data
- Checksum field itself is replaced with zeros during computation
- If segment has odd number of octets, pad with a zero octet for checksum purposes (not transmitted)
- Store the ones' complement of the sum in the checksum field

**Requirements:**
- Sender MUST compute checksum (MUST-2)
- Receiver MUST verify checksum (MUST-3)
- Checksum is NEVER optional

---

## 2. Options

### Mandatory Options (MUST-4)

| Kind | Length | Total Bytes | Name |
|------|--------|-------------|------|
| 0 | - | 1 | End of Option List (EOL) — no length field (single-octet option) |
| 1 | - | 1 | No-Operation (NOP) — no length field (single-octet option, used for alignment padding) |
| 2 | 4 | 4 | Maximum Segment Size (MSS) — SYN segments only (MUST NOT send on non-SYN, MUST-65) |

### Recommended Options (not required for compliance)

| Kind | Length | Name | RFC |
|------|--------|------|-----|
| 3 | 3 | Window Scale (WS) | 7323 |
| 4 | 2 | SACK Permitted | 2018 |
| 5 | var | SACK | 2018 |
| 8 | 10 | Timestamps (TS) | 7323 |

### Option Processing Rules

- MUST receive options in any segment (MUST-5)
- MUST ignore unknown options with length fields (MUST-6)
- All options except EOL and NOP MUST have length fields (MUST-68)
- MUST handle illegal option lengths (e.g., zero) - suggested: reset + log (MUST-7)
- MUST process options regardless of word alignment (MUST-64)
- Padding after options MUST be zeros (MUST-69)

---

## 3. Transmission Control Block (TCB)

The TCB holds all per-connection state.

### Send Sequence Variables

| Variable | Description |
|----------|-------------|
| SND.UNA | Oldest unacknowledged sequence number |
| SND.NXT | Next sequence number to send |
| SND.WND | Send window (octets peer will accept) |
| SND.UP | Send urgent pointer |
| SND.WL1 | Segment seq used for last window update |
| SND.WL2 | Segment ack used for last window update |
| ISS | Initial send sequence number |

### Receive Sequence Variables

| Variable | Description |
|----------|-------------|
| RCV.NXT | Next expected receive sequence number (left edge of receive window) |
| RCV.WND | Receive window size |
| RCV.UP | Receive urgent pointer |
| IRS | Initial receive sequence number |

### Current Segment Variables (per-packet, not stored)

| Variable | Description |
|----------|-------------|
| SEG.SEQ | Segment sequence number |
| SEG.ACK | Segment acknowledgment number |
| SEG.LEN | Segment length (data + SYN/FIN occupy sequence space) |
| SEG.WND | Segment window |
| SEG.UP | Segment urgent pointer |

### Additional TCB Fields

- Local/remote IP + port (connection identity / 4-tuple)
- Connection state (see state machine)
- Send/receive buffers and retransmission queue
- RTO timer state (SRTT, RTTVAR, RTO per RFC 6298)
- Whether connection originated from passive or active OPEN (MUST-11)
- User timeout value
- Congestion control state (cwnd, ssthresh)
- MAX.SND.WND - largest window ever received (for RFC 5961)

---

## 4. Sequence Number Arithmetic

All sequence number math is **modulo 2^32**.

### Comparisons

Use wrapping comparison (treating as signed difference):

```
a < b  iff  (a - b) as i32 < 0   (wrapping subtraction)
a <= b iff  (a - b) as i32 <= 0
```

### Key Tests

**Acceptable ACK:**
```
SND.UNA < SEG.ACK <= SND.NXT
```

**Segment fully acknowledged** (for retransmit queue removal):
```
SEG.SEQ + SEG.LEN <= SEG.ACK  (from the ACK)
```

**Segment acceptability** (4 cases):

| Seg Len | Recv Win | Test |
|---------|----------|------|
| 0 | 0 | SEG.SEQ == RCV.NXT |
| 0 | >0 | RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND |
| >0 | 0 | NOT acceptable |
| >0 | >0 | RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND **OR** RCV.NXT <= SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND |

When RCV.WND is zero: still MUST process RST and URG fields (MUST-66).

### SYN and FIN in Sequence Space

- SYN occupies 1 sequence number, positioned BEFORE any data in the segment
- FIN occupies 1 sequence number, positioned AFTER the last data octet
- SEG.LEN includes data + SYN (if present) + FIN (if present)
- When SYN is present, SEG.SEQ is the sequence number of the SYN

---

## 5. Initial Sequence Number (ISN) Selection

MUST use a clock-driven scheme (MUST-8).

SHOULD use the following formula (SHLD-1):

```
ISN = M + F(local_ip, local_port, remote_ip, remote_port, secret_key)
```

- **M**: 32-bit counter incrementing ~every 4 microseconds (cycles every ~4.55 hours)
- **F()**: PRF (e.g., cryptographic hash) — MUST NOT be computable from outside (MUST-9)
- **secret_key**: random, unknown to attackers

The PRF prevents off-path attackers from predicting ISNs.

Note: The specific formula is SHLD-1 (a SHOULD recommendation). Any clock-driven ISN selection that satisfies MUST-8 and MUST-9 is compliant.

### Quiet Time Concept

After a reboot or crash that loses memory of sequence numbers in use, a host should delay at least MSL (2 minutes) before emitting any TCP segments, to avoid overlap with potentially still in-flight segments from prior connection incarnations. This is the "quiet time" specification.

In practice, this is considered safe to ignore on modern networks because: (a) ISS and ephemeral port randomization reduce reuse likelihood, (b) effective MSL of the Internet has declined, and (c) reboots typically take longer than MSL. Implementations MAY violate quiet time, at the risk of old data being accepted as new.

### High-Speed Sequence Space Concerns (PAWS)

At high data rates the 32-bit sequence space cycles quickly:
- 1 Gbps: 34 seconds
- 10 Gbps: 3 seconds
- 100 Gbps: ~0.3 seconds

These cycle times can be shorter than MSL, so TCP Timestamp Options and Protection Against Wrapped Sequences (PAWS, RFC 7323) are needed to detect and discard old duplicates at high speeds.

---

## 6. Connection State Machine

### States

| State | Description |
|-------|-------------|
| CLOSED | No connection (fictional - no TCB exists) |
| LISTEN | Waiting for incoming SYN (passive open) |
| SYN-SENT | SYN sent, waiting for SYN-ACK (active open) |
| SYN-RECEIVED | SYN received and SYN-ACK sent, waiting for ACK |
| ESTABLISHED | Connection open, data transfer |
| FIN-WAIT-1 | FIN sent, waiting for ACK of FIN or remote FIN |
| FIN-WAIT-2 | Our FIN ACKed, waiting for remote FIN |
| CLOSE-WAIT | Remote FIN received, waiting for local CLOSE |
| CLOSING | Both sides sent FIN, waiting for ACK of our FIN |
| LAST-ACK | Remote FIN received + our FIN sent, waiting for ACK |
| TIME-WAIT | Waiting 2*MSL before deleting TCB |

### Key Transitions

```
CLOSED --[passive OPEN]--> LISTEN
CLOSED --[active OPEN, send SYN]--> SYN-SENT

LISTEN --[rcv SYN, send SYN,ACK]--> SYN-RECEIVED
LISTEN --[active OPEN, send SYN]--> SYN-SENT

SYN-SENT --[rcv SYN,ACK, send ACK]--> ESTABLISHED
SYN-SENT --[rcv SYN (no ACK), send SYN,ACK]--> SYN-RECEIVED  (simultaneous open)

SYN-RECEIVED --[rcv ACK of SYN]--> ESTABLISHED
SYN-RECEIVED --[rcv RST, was passive]--> LISTEN
SYN-RECEIVED --[rcv RST, was active]--> CLOSED
SYN-RECEIVED --[CLOSE, send FIN]--> FIN-WAIT-1

ESTABLISHED --[CLOSE, send FIN]--> FIN-WAIT-1
ESTABLISHED --[rcv FIN, send ACK]--> CLOSE-WAIT

FIN-WAIT-1 --[rcv ACK of FIN]--> FIN-WAIT-2
FIN-WAIT-1 --[rcv FIN, send ACK]--> CLOSING
FIN-WAIT-1 --[rcv FIN+ACK of FIN, send ACK]--> TIME-WAIT

FIN-WAIT-2 --[rcv FIN, send ACK]--> TIME-WAIT

CLOSE-WAIT --[CLOSE, send FIN]--> LAST-ACK

CLOSING --[rcv ACK of FIN]--> TIME-WAIT

LAST-ACK --[rcv ACK of FIN]--> CLOSED (delete TCB)

TIME-WAIT --[2*MSL timeout]--> CLOSED (delete TCB)
```

**Requirements:**
- MUST support simultaneous open (MUST-10)
- MUST track whether SYN-RECEIVED came from passive or active OPEN (MUST-11)
- TIME-WAIT MUST last 2*MSL (MUST-13). MSL = 2 minutes.
- MAY accept new SYN from TIME-WAIT if new ISN > largest sequence number used on previous incarnation; returns to TIME-WAIT if old dup (MAY-2)
- SHOULD use Timestamps to reduce TIME-WAIT duration when Timestamp Options are in use (SHLD-4)

---

## 7. Connection Establishment (Three-Way Handshake)

### Normal 3WHS

```
A (CLOSED)                              B (LISTEN)
  SYN-SENT --> <SEQ=ISS_A><CTL=SYN>               --> SYN-RECEIVED
  ESTABLISHED <-- <SEQ=ISS_B><ACK=ISS_A+1><CTL=SYN,ACK> <-- SYN-RECEIVED
  ESTABLISHED --> <SEQ=ISS_A+1><ACK=ISS_B+1><CTL=ACK>   --> ESTABLISHED
```

### Simultaneous Open

Both peers send SYN before receiving peer's SYN.
Each transitions: CLOSED -> SYN-SENT -> SYN-RECEIVED -> ESTABLISHED.

### Old Duplicate SYN Recovery

If a stale SYN arrives at a listener, the listener sends SYN-ACK.
The original sender detects incorrect ACK field, sends RST.
Listener returns to LISTEN.

### Half-Open Connections

An established connection is "half-open" if one side has closed/crashed without the other knowing, or if the two ends become desynchronized. Half-open connections are automatically reset when data transfer is attempted:

**Case 1 — Crashed side reopens:** A reboots, sends new SYN. B (still ESTABLISHED) replies with ACK for old sequence. A detects unacceptable ACK, sends RST. B aborts. Then normal 3WHS proceeds.

**Case 2 — Live side sends data:** B sends data to rebooted A. A has no TCB for this connection, sends RST. B aborts.

**Case 3 — Old duplicate SYN to two passive sockets:** A stale SYN triggers SYN-ACK from a listener. The peer (also in LISTEN) generates RST because the ACK is unacceptable. Original listener returns to LISTEN.

These cases are all handled by the RST generation and processing rules in Section 8.

---

## 8. Reset (RST) Generation and Processing

### When to Generate RST

The side of a connection issuing a reset SHOULD enter the TIME-WAIT state, as this helps reduce load on busy servers (see RFC reference on TIME-WAIT effects).

**CLOSED state:** Any non-RST segment -> send RST.
- ACK off: `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`
- ACK on: `<SEQ=SEG.ACK><CTL=RST>`

**Non-synchronized states (LISTEN, SYN-SENT, SYN-RECEIVED):**
Unacceptable ACK -> send RST (same format rules as CLOSED).

**Synchronized states (ESTABLISHED through TIME-WAIT):**
- Out-of-window segment: send ACK (not RST), stay in same state
- Security mismatch: send RST, close connection

### RST Processing

**Validation:**
- SYN-SENT: RST valid only if ACK field acknowledges our SYN; if no ACK present, drop RST
- All other states: RST valid if SEQ is in the receive window

**RFC 5961 mitigation (SHOULD implement for non-SYN-SENT states):**
1. RST with SEQ outside window: silently drop
2. RST with SEQ == RCV.NXT: reset connection per state rules
3. RST with SEQ in window but != RCV.NXT: send challenge ACK, drop segment

**State-specific RST actions:**
- LISTEN: ignore RST
- SYN-RECEIVED from passive OPEN: return to LISTEN
- SYN-RECEIVED from active OPEN: signal "connection refused", delete TCB -> CLOSED
- ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT: signal "connection reset", delete TCB -> CLOSED
- CLOSING, LAST-ACK, TIME-WAIT: delete TCB -> CLOSED

RST SHOULD be allowed to contain data (SHLD-2).

---

## 9. Connection Closing

### Normal Close (FIN Handshake)

```
A (ESTABLISHED)                              B (ESTABLISHED)
  FIN-WAIT-1 --> <FIN,ACK>                         --> CLOSE-WAIT
  FIN-WAIT-2 <-- <ACK>                             <-- CLOSE-WAIT
  TIME-WAIT  <-- <FIN,ACK>                         <-- LAST-ACK
  TIME-WAIT  --> <ACK>                              --> CLOSED
  (2*MSL) -> CLOSED
```

### Simultaneous Close

Both send FIN before receiving peer's FIN.
Both transition: ESTABLISHED -> FIN-WAIT-1 -> CLOSING -> TIME-WAIT -> CLOSED

### Half-Closed Connections

After sending FIN, a side can still receive data. After receiving FIN, a side can still send data (CLOSE-WAIT state). Connection is fully closed only when both sides have sent and acknowledged FINs.

**Half-duplex close (MAY-1):** Implementation MAY prevent reading after CLOSE. If so, and data is pending or arrives, SHOULD send RST (SHLD-3).

### Requirements

- Application MUST be informed whether close was normal (FIN) or abort (RST) (MUST-12)
- TIME-WAIT MUST linger for 2*MSL (MUST-13)
- FIN implies PUSH for any buffered data

---

## 10. Segmentation

### Maximum Segment Size (MSS)

MUST implement send and receive of MSS option (MUST-14).

**MSS Option:** Only in SYN segments (MUST-65). 4 bytes: Kind=2, Length=4, MSS value (16-bit).

**Defaults when no MSS option received:**
- IPv4: 536 (576 - 40) (MUST-15)
- IPv6: 1220 (1280 - 60) (MUST-15)

**Effective send MSS calculation (MUST-16):**
```
Eff.snd.MSS = min(SendMSS + 20, MMS_S) - TCPhdrsize - IPoptionsize
```
- SendMSS = received MSS value (or default)
- MMS_S = max transport-layer message size from IP layer
- TCPhdrsize = TCP header including options (>= 20)
- IPoptionsize = IP options/extension headers size

**MSS value to send (MUST-67):**
```
MSS_to_send <= MMS_R - 20
```
Where MMS_R is max receivable transport message (from IP layer). MAY always send MSS option (MAY-3).

SHOULD send MSS option in SYN when receive MSS differs from default (SHLD-5).
When interface has variable MTU, SHOULD use the smallest effective MTU for MSS calculation (SHLD-6).

### Path MTU Discovery

Strongly recommended (PMTUD per RFC 1191/8201, PLPMTUD per RFC 4821). Not required for basic compliance but essential for performance.

### IPv6 Jumbograms

To support TCP over IPv6 Jumbograms (RFC 2675), implementations need to send TCP segments larger than the 64 KB limit the MSS Option can convey. An MSS value of 65,535 bytes is treated as infinity, and Path MTU Discovery is used to determine the actual MSS. Support for Jumbograms is not required by IPv6 Node Requirements (RFC 8504) unless attached to links with MTU > 65,575.

### Nagle Algorithm

SHOULD implement (SHLD-7). Application MUST be able to disable it (MUST-17, i.e., TCP_NODELAY).

**Rule:** If unacknowledged data exists (SND.NXT > SND.UNA), buffer all new data until:
- Outstanding data is acknowledged, OR
- A full-sized segment (Eff.snd.MSS) can be sent

**Nagle Modification (Minshall):** A common modification improves performance for request-response protocols where the combination of Nagle + delayed ACKs causes poor latency. Instead of checking `SND.NXT > SND.UNA` (is there unacknowledged data?), check whether the last transmission was less than a full segment. This is implemented in some OSes and does not impact interoperability. Not yet part of the standard, but implementers may find it beneficial.

---

## 11. Data Communication

### Retransmission Timeout (RTO)

MUST compute RTO per RFC 6298 (MUST-18), including Karn's algorithm:
- Don't use RTT samples from retransmitted segments
- Use exponential backoff on retransmission

**RFC 6298 algorithm summary:**
```
On first RTT measurement R:
  SRTT = R
  RTTVAR = R/2
  RTO = SRTT + max(G, 4 * RTTVAR)   where G = clock granularity

On subsequent measurements R':
  RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|    (beta = 1/4)
  SRTT = (1 - alpha) * SRTT + alpha * R'                (alpha = 1/8)
  RTO = SRTT + max(G, 4 * RTTVAR)

Constraints:
  RTO >= 1 second (initial RTO = 1 second)
  On retransmit: RTO = RTO * 2 (exponential backoff)
  After successful ACK of new data: restore RTO from SRTT/RTTVAR
```

If a retransmitted packet is identical to the original, the same IPv4 Identification field MAY be reused (MAY-4), though this field is only meaningful for fragmented datagrams and TCP should not rely on it.

### Congestion Control

MUST implement (MUST-19):
- **Slow start**: cwnd starts at IW (initial window), increases by 1 MSS per ACK during slow start
- **Congestion avoidance**: linear increase after cwnd >= ssthresh
- **Exponential backoff**: RTO doubles on each retransmit timeout

An endpoint MAY implement alternative conformant congestion control algorithms (MAY-18), provided they comply with RFC 2914, RFC 5033, and RFC 8961.

SHOULD implement ECN (SHLD-8, RFC 3168).

Reference: RFC 5681 (slow start, congestion avoidance, fast retransmit, fast recovery).

### Connection Failures

Two thresholds R1 and R2 (MUST-20):
- **R1** (SHOULD >= 3 retransmissions, SHLD-10): trigger negative advice to IP layer
- **R2** (SHOULD >= 100 seconds, SHLD-11): close the connection
- Application MUST be able to set R2 (MUST-21)
- SHOULD inform application between R1 and R2 (SHLD-9)
- SYN retransmissions MUST use the same R1/R2 mechanism as data retransmissions (MUST-22)
- SYN retransmissions: R2 MUST be >= 3 minutes (MUST-23)

### Keep-Alives

MAY implement (MAY-5). If implemented:
- Application MUST be able to enable/disable per connection (MUST-24)
- MUST default to off (MUST-25)
- MUST only send when no sent data is outstanding AND no data/ACK received for configured interval (MUST-26)
- Interval MUST be configurable (MUST-27), default >= 2 hours (MUST-28)
- MUST NOT treat single probe failure as dead connection (MUST-29)
- Keep-alive probe: `SEG.SEQ = SND.NXT - 1`, no data (SHLD-12) or 1 garbage octet (MAY-6)

---

## 12. Urgent Mechanism

New applications SHOULD NOT use it (SHLD-13), but MUST still support it (MUST-30).

- Urgent pointer = offset from SEQ to octet AFTER urgent data (MUST-62)
- MUST support arbitrary length urgent data (MUST-31)
- MUST inform application asynchronously when urgent pointer arrives/advances (MUST-32)
- MUST let application query how much urgent data remains (MUST-33)
- When RCV.UP > data consumed: user in "urgent mode"
- When data consumed catches up to RCV.UP: user leaves "urgent mode"

---

## 13. Window Management

### Window Update Rule

Applies when `SND.UNA <= SEG.ACK <= SND.NXT` (note: inclusive of `==` on left, so duplicate ACKs can carry window updates).

Update send window when (prevents stale window info):
```
SND.WL1 < SEG.SEQ OR (SND.WL1 == SEG.SEQ AND SND.WL2 <= SEG.ACK)
```
Then set:
```
SND.WND = SEG.WND
SND.WL1 = SEG.SEQ
SND.WL2 = SEG.ACK
```

### Receiver SHOULD NOT shrink window (SHLD-14)

Sender MUST be robust against window shrinking (MUST-34). If usable window goes negative:
- SHOULD NOT send new data (SHLD-15)
- SHOULD retransmit old unacked data in [SND.UNA, SND.UNA+SND.WND] (SHLD-16)
- MAY retransmit old data beyond SND.UNA+SND.WND (MAY-7)
- SHOULD NOT time out the connection if data beyond the right window edge is not acknowledged (SHLD-17)
- If window shrinks to zero: MUST probe (MUST-35)

### Zero-Window Probing

MUST support (MUST-36). Sender periodically sends 1 octet to probe a zero window.
- First probe SHOULD occur after RTO (SHLD-29)
- SHOULD exponentially backoff probe interval (SHLD-30)
- MUST keep connection open as long as receiver ACKs probes (MUST-37)
- A receiver MAY keep its offered receive window closed indefinitely (MAY-8)

### Silly Window Syndrome (SWS) Avoidance

MUST include SWS avoidance in sender (MUST-38) and receiver (MUST-39).

**Sender's algorithm - when to send:**

Usable window: `U = SND.UNA + SND.WND - SND.NXT`

Send if any of:
1. Can send full-sized segment: `min(D, U) >= Eff.snd.MSS`
2. Data is pushed, all queued data fits, and (Nagle allows): `PUSHed AND D <= U [AND SND.NXT == SND.UNA]`
3. At least half max window: `min(D, U) >= 0.5 * Max(SND.WND) [AND SND.NXT == SND.UNA]`
4. Override timeout fires (0.1 - 1.0 seconds)

**Receiver's algorithm - when to update window:**

Keep `RCV.NXT + RCV.WND` fixed until:
```
RCV.BUFF - RCV.USER - RCV.WND >= min(0.5 * RCV.BUFF, Eff.snd.MSS)
```
Then set `RCV.WND = RCV.BUFF - RCV.USER`.

### Delayed ACKs

SHOULD implement delayed ACKs (SHLD-18):
- Delay MUST be < 500ms (MUST-40)
- SHOULD ACK at least every 2nd full-sized segment or 2*RMSS bytes (SHLD-19)
- Immediately ACK out-of-order segments and segments filling gaps

---

## 14. User/TCP Interface

These are the logical operations the TCP stack must provide.

### OPEN

`OPEN(local_port, remote_socket, active/passive, [timeout], [dscp], [local_ip]) -> connection_name`

- **Passive:** Enter LISTEN state. Each passive OPEN creates new connection record (MUST NOT affect existing, MUST-41).
- **Active:** Send SYN, enter SYN-SENT. Remote socket must be specified.
- MUST support concurrent LISTEN while SYN-SENT/SYN-RECEIVED exists on same port (MUST-42)
- MUST support local IP address parameter (MUST-43)
- On multihomed active open without specified local IP: MUST ask IP layer for source address before sending SYN (MUST-44)
- MUST use same local address for all segments on a connection (MUST-45)
- MUST reject OPEN to broadcast/multicast address (MUST-46)

**PUSH flags:** A TCP endpoint MAY implement PUSH flags on SEND calls (MAY-15). If PUSH flags are not implemented, then: (1) the sender MUST NOT buffer data indefinitely (MUST-60), and (2) MUST set PSH on the last buffered segment (MUST-61). When an application issues a series of SENDs without setting the PUSH flag, TCP MAY aggregate the data internally without sending it (MAY-16). A TCP receiver MAY pass a received PSH bit to the application layer (MAY-17).

### SEND

`SEND(connection, buffer, byte_count, urgent_flag, [push_flag], [timeout])`

- If PUSH supported: PSH causes prompt transmission
- SHOULD collapse successive PSH bits to send the largest possible segment (SHLD-27)
- SHOULD send maximum-sized segments (SHLD-28)

### RECEIVE

`RECEIVE(connection, buffer, byte_count) -> byte_count, urgent_flag, [push_flag]`

- Deliver data from receive buffer. Returns PUSH/URGENT status.

### CLOSE

`CLOSE(connection)`

- Graceful close. Queue remaining data, send FIN.
- CLOSE implies PUSH for buffered data.
- User should continue to RECEIVE after CLOSE (remote may still be sending).

### ABORT

`ABORT(connection)`

- Immediate teardown. Send RST, flush queues, delete TCB.

### STATUS

`STATUS(connection) -> state_info`

- Returns connection state, window sizes, addresses, etc.

### FLUSH

`FLUSH(connection)`

- Empty the TCP send queue of data that is still to the right of the current send window (MAY-14). Flushes as much queued send data as possible without losing sequence number synchronization.

### Asynchronous Reports

MUST report soft errors to application (MUST-47):
- ICMP errors, excessive retransmissions, urgent pointer advance
- Application SHOULD be able to disable reports (SHLD-20)

### Differentiated Services

- Application MUST be able to specify DSCP for outgoing segments (MUST-48)
- SHOULD be changeable during connection (SHLD-21)
- SHOULD pass to IP unchanged (SHLD-22)
- Application generally SHOULD NOT change DSCP during a connection (SHLD-23)
- MAY pass most recently received Diffserv field up to the application (MAY-9)

### 14.1 Per-State Processing of User Calls

The following details how each user call is processed depending on the current connection state.

#### OPEN Call

| State | Action |
|-------|--------|
| CLOSED | Create TCB. If passive: enter LISTEN, return. If active: select ISS, send `<SEQ=ISS><CTL=SYN>`, set SND.UNA=ISS, SND.NXT=ISS+1, enter SYN-SENT. Error if active and remote socket unspecified. |
| LISTEN | If active OPEN with remote socket specified: select ISS, send `<SEQ=ISS><CTL=SYN>`, set SND.UNA=ISS, SND.NXT=ISS+1, enter SYN-SENT. Data from SEND may be sent with SYN or queued. Error if remote unspecified. |
| All others | Return "error: connection already exists". |

#### SEND Call

| State | Action |
|-------|--------|
| CLOSED | Return "error: connection does not exist". |
| LISTEN | If remote socket specified: transition to active, select ISS, send SYN, enter SYN-SENT. Data may be sent with SYN or queued. Error if remote unspecified. |
| SYN-SENT, SYN-RECEIVED | Queue data for transmission after entering ESTABLISHED. |
| ESTABLISHED, CLOSE-WAIT | Segmentize buffer and send with piggybacked ACK (ACK=RCV.NXT). If URGENT flag set: SND.UP <- SND.NXT, set urgent pointer in outgoing segments. |
| FIN-WAIT-1/2, CLOSING, LAST-ACK, TIME-WAIT | Return "error: connection closing". |

#### RECEIVE Call

| State | Action |
|-------|--------|
| CLOSED | Return "error: connection does not exist". |
| LISTEN, SYN-SENT, SYN-RECEIVED | Queue for processing after entering ESTABLISHED. |
| ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 | If insufficient data queued: queue the request. Otherwise: reassemble into receive buffer, return to user. Mark PUSH if seen. Notify user of urgent data if RCV.UP is ahead of consumed data. |
| CLOSE-WAIT | Serve from already-received data only. If no data awaiting delivery: return "error: connection closing". |
| CLOSING, LAST-ACK, TIME-WAIT | Return "error: connection closing". |

#### CLOSE Call

| State | Action |
|-------|--------|
| CLOSED | Return "error: connection does not exist". |
| LISTEN | Return outstanding RECEIVEs with "error: closing". Delete TCB, enter CLOSED. |
| SYN-SENT | Delete TCB. Return "error: closing" to queued SENDs/RECEIVEs. |
| SYN-RECEIVED | If no pending data: send FIN, enter FIN-WAIT-1. Otherwise: queue for processing after ESTABLISHED. |
| ESTABLISHED | Queue until all preceding SENDs are segmentized, then send FIN. Enter FIN-WAIT-1. |
| FIN-WAIT-1, FIN-WAIT-2 | Return "error: connection closing" (strictly an error; a second FIN MUST NOT be sent). |
| CLOSE-WAIT | Queue until all preceding SENDs are segmentized, then send FIN. Enter LAST-ACK. |
| CLOSING, LAST-ACK, TIME-WAIT | Return "error: connection closing". |

#### ABORT Call

| State | Action |
|-------|--------|
| CLOSED | Return "error: connection does not exist". |
| LISTEN | Return outstanding RECEIVEs with "connection reset". Delete TCB, enter CLOSED. |
| SYN-SENT | Notify queued SENDs/RECEIVEs "connection reset". Delete TCB, enter CLOSED. |
| SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT | Send `<SEQ=SND.NXT><CTL=RST>`. Notify all queued SENDs/RECEIVEs "connection reset". Flush all segment queues. Delete TCB, enter CLOSED. |
| CLOSING, LAST-ACK, TIME-WAIT | Delete TCB, enter CLOSED. |

---

## 15. TCP/Lower-Level Interface

### IP Interface

- TTL MUST be configurable (MUST-49)
- MUST ignore unknown IP options (MUST-50)
- MAY support IP Timestamp option (MAY-10)
- MAY support IP Record Route option (MAY-11)

### Source Routing

- Application MUST be able to specify source route on active open (MUST-51, takes precedence MUST-52)
- On passive open with source route: MUST save and use return route (MUST-53)
- Later source route SHOULD override (SHLD-24)

### ICMP Processing

MUST act on ICMP errors directed to connection (MUST-54).

| ICMP Type | Action |
|-----------|--------|
| Source Quench | MUST silently discard (MUST-55) |
| Dest Unreachable codes 0,1,5 (IPv4) / 0,3 (IPv6) | Soft error. MUST NOT abort (MUST-56). SHOULD inform app (SHLD-25). |
| Time Exceeded, Parameter Problem | Soft error. Same as above. |
| Dest Unreachable codes 2-4 (IPv4) | Hard error. SHOULD abort connection (SHLD-26). |

### Address Validation

- MUST ignore/reject segments with invalid source address (MUST-63) — applies to all incoming segments, not just SYNs
- MUST silently discard SYN to broadcast/multicast address (MUST-57)

---

## 16. Segment Processing (Event Machine)

This is the core state machine. Processing order matters.

### 16.1 CLOSED State (no TCB)

Any non-RST segment: send RST.
- ACK off: `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`
- ACK on: `<SEQ=SEG.ACK><CTL=RST>`
- RST segment: discard.

### 16.2 LISTEN State

Process in order:

1. **RST:** Ignore. Return.
2. **ACK:** Bad. Send `<SEQ=SEG.ACK><CTL=RST>`. Return.
3. **SYN:** Check security. If listen was not fully specified (wildcard remote), fill in unspecified fields now. Set RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ. Select ISS. Send `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`. Set SND.NXT = ISS+1, SND.UNA = ISS. Enter SYN-RECEIVED. Queue any data/controls for later processing.
4. **Other:** Drop segment.

### 16.3 SYN-SENT State

Process in order:

1. **Check ACK:** If ACK set:
   - If `SEG.ACK <= ISS` or `SEG.ACK > SND.NXT`: send RST `<SEQ=SEG.ACK><CTL=RST>` (unless RST set), discard, return.
   - Acceptable if `SND.UNA < SEG.ACK <= SND.NXT`.

2. **Check RST:** If RST set:
   - RFC 5961: SHOULD check SEG.SEQ == RCV.NXT first
   - If ACK was acceptable: signal "connection reset", delete TCB -> CLOSED
   - If no ACK: drop segment, return

3. **Check security:** If security/compartment mismatch:
   - ACK present: send `<SEQ=SEG.ACK><CTL=RST>`, discard, return
   - No ACK: send `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, discard, return

4. **Check SYN:** If SYN set:
   - Set RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ
   - Advance SND.UNA to SEG.ACK (if ACK present), remove acknowledged segments from retransmit queue
   - If `SND.UNA > ISS` (our SYN has been ACKed):
     - Enter ESTABLISHED
     - Send `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`
     - Set SND.WND = SEG.WND, SND.WL1 = SEG.SEQ, SND.WL2 = SEG.ACK
     - Note: The RFC says to continue at step 6 (URG check), skipping step 5 (ACK check). Implementations MUST explicitly set SND.WND/WL1/WL2 here (as the simultaneous open case does) since step 5's window update logic will not run for this path.
     - Continue to step 6 (URG check) of "Other States" if segment has data/controls; otherwise return
   - Else (simultaneous open):
     - Enter SYN-RECEIVED
     - Send `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`
     - Set SND.WND = SEG.WND, SND.WL1 = SEG.SEQ, SND.WL2 = SEG.ACK
     - Queue any data for processing after ESTABLISHED
   - Note: Data on SYN segments is legal (see TCP Fast Open, RFC 7413)

5. **Neither SYN nor RST:** Drop segment.

### 16.4 All Other States (SYN-RECEIVED through TIME-WAIT)

Process in order:

#### Step 1: Check Sequence Number

Apply segment acceptability test (see Section 4 table above).

- Unacceptable and RST set: drop segment, return
- Unacceptable and RST not set: send `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`, drop, return
- If RCV.WND is zero: still MUST accept valid ACKs, URGs, and RSTs
- If acceptable, trim segment to fit window (including trimming SYN and FIN if they fall outside the window). Hold out-of-order segments (SHLD-31).
- In TIME-WAIT: an improved algorithm using Timestamps may override normal sequence checking for incoming SYNs (see RFC 6191)
- MUST aggregate ACKs when processing queued segments (MUST-58, MUST-59)

#### Step 2: Check RST

**With RFC 5961 mitigation:**
1. SEQ outside window: silently drop
2. SEQ == RCV.NXT: reset per state rules below
3. SEQ in window but != RCV.NXT: MUST send challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`, MUST drop segment

Note: RFC 5961 and Errata ID 4772 contain additional considerations for ACK throttling to prevent amplification.

**State-specific reset actions:**
- **SYN-RECEIVED:** If from passive OPEN -> flush retransmission queue, return to LISTEN. If from active OPEN -> signal "refused", flush retransmission queue, delete TCB -> CLOSED.
- **ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT:** Return "reset" responses to outstanding RECEIVEs/SENDs, flush all segment queues, signal "connection reset" to user, delete TCB -> CLOSED.
- **CLOSING, LAST-ACK, TIME-WAIT:** Delete TCB -> CLOSED.

#### Step 3: Check Security

If security/compartment mismatch: send RST, CLOSED. (MLS systems only; ignore for non-MLS.)

#### Step 4: Check SYN

- **SYN-RECEIVED (passive):** Return to LISTEN.
- **SYN-RECEIVED (active, i.e., simultaneous open):** Handle per synchronized states below.
- **All synchronized states (ESTABLISHED through TIME-WAIT):** RFC 5961: MUST send challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`, MUST drop segment. (Without RFC 5961: if SYN in window, send RST, close connection.)
- Note: ACK throttling considerations from RFC 5961 and Errata ID 4772 apply here as well.

#### Step 5: Check ACK

If ACK bit off: drop segment, return.

If ACK bit on:

**RFC 5961 ACK validation (MAY-12):** Accept only if `(SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT`. Otherwise discard + send ACK.

**SYN-RECEIVED:**
- `SND.UNA < SEG.ACK <= SND.NXT`: enter ESTABLISHED. Set SND.WND, SND.WL1, SND.WL2. **Continue processing** through subsequent steps (URG, data, FIN) in ESTABLISHED state.
- Otherwise: send RST `<SEQ=SEG.ACK><CTL=RST>`.

**ESTABLISHED:**
- `SND.UNA < SEG.ACK <= SND.NXT` (new ACK): advance SND.UNA, remove acked segments from retransmit queue, return positive acknowledgments for completed SEND buffers.
- `SEG.ACK <= SND.UNA` (duplicate ACK): can be ignored for advancement purposes, but still check window update below.
- `SEG.ACK > SND.NXT` (future ACK): send ACK, drop, return.
- **Window update** (applies when `SND.UNA <= SEG.ACK <= SND.NXT`, note `<=` on left — includes duplicate ACKs): If `SND.WL1 < SEG.SEQ` or (`SND.WL1 == SEG.SEQ` and `SND.WL2 <= SEG.ACK`): update SND.WND, SND.WL1, SND.WL2.

**FIN-WAIT-1:** Same as ESTABLISHED, plus: if our FIN is now ACKed -> FIN-WAIT-2, continue processing in that state.

**FIN-WAIT-2:** Same as ESTABLISHED, plus: if retransmit queue empty, signal app "close ok".

**CLOSE-WAIT:** Same as ESTABLISHED.

**CLOSING:** Same as ESTABLISHED, plus: if our FIN is ACKed -> TIME-WAIT; otherwise, ignore the segment.

**LAST-ACK:** If our FIN is ACKed: delete TCB -> CLOSED. Return.

**TIME-WAIT:** Only retransmitted FIN can arrive. ACK it, restart 2*MSL timer.

#### Step 6: Check URG

**ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2:**
- If URG set: `RCV.UP = max(RCV.UP, SEG.UP)`. Signal user if RCV.UP is ahead of consumed data (don't re-signal if already in urgent mode for same sequence).

**CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT:** Ignore URG (FIN already received).

#### Step 7: Process Segment Data

**ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2:**
- Deliver data to receive buffer
- If segment carries PSH flag and empties, inform user that PUSH has been received when buffer is returned
- Advance RCV.NXT over accepted data
- Adjust RCV.WND (total of RCV.NXT+RCV.WND should not decrease)
- Send ACK: `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` (piggyback if possible)
- MAY send ACK for valid out-of-order segments (MAY-13)

**CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT:** Ignore data (FIN already received).

#### Step 8: Check FIN

Do NOT process FIN in CLOSED, LISTEN, or SYN-SENT (SEQ cannot be validated).

If FIN bit set:
- Signal user "connection closing"
- Return pending RECEIVEs with "closing" message
- Advance RCV.NXT over the FIN
- Send ACK for the FIN
- FIN implies PUSH for any undelivered data

**State transitions on FIN:**
- **SYN-RECEIVED, ESTABLISHED:** -> CLOSE-WAIT
- **FIN-WAIT-1:** If our FIN also ACKed in this segment -> TIME-WAIT (start 2*MSL timer, turn off other timers). Else -> CLOSING.
- **FIN-WAIT-2:** -> TIME-WAIT (start 2*MSL timer, turn off other timers)
- **CLOSE-WAIT, CLOSING, LAST-ACK:** Remain in same state.
- **TIME-WAIT:** Remain. Restart 2*MSL timer.

---

## 17. Timeouts

### User Timeout

Any state: flush all queues, signal "connection aborted due to user timeout" (both general and for any outstanding SENDs/RECEIVEs), delete TCB -> CLOSED.

### Retransmission Timeout

Any state: retransmit segment at front of retransmission queue, reinitialize RTO (with backoff).

### TIME-WAIT Timeout

2*MSL expires: delete TCB -> CLOSED.

---

## 18. Implementation Modules Breakdown

For a clean implementation, the following modules/components are suggested:

### Module 1: Wire Format (Parsing & Serialization)
- TCP header read/write (20-60 bytes)
- Option parsing (EOL, NOP, MSS, + extensible for WS, SACK, Timestamps)
- Checksum computation (with IPv4/IPv6 pseudo-header)
- Segment length calculation (data + SYN + FIN)

### Module 2: Sequence Number Arithmetic
- Wrapping u32 comparison operators (`<`, `<=`, `==`, `>=`, `>`)
- Wrapping addition/subtraction
- Window containment tests

### Module 3: Transmission Control Block (TCB)
- All per-connection state variables
- Connection identification (4-tuple: local_ip, local_port, remote_ip, remote_port)
- State enum
- Send/receive buffers
- Retransmission queue

### Module 4: ISN Generator
- Clock-driven 4us counter
- PRF: HMAC or SipHash over (local_ip, local_port, remote_ip, remote_port, secret)
- ISN = clock + PRF output

### Module 5: Connection State Machine
- State transition logic (Section 16 above)
- OPEN/SEND/RECEIVE/CLOSE/ABORT/STATUS call handling
- Segment arrival processing (the 8-step processing pipeline)

### Module 6: Timer Management
- Retransmission timer (per RFC 6298)
- TIME-WAIT timer (2*MSL = 4 minutes)
- User timeout
- Zero-window probe timer
- Keep-alive timer
- Delayed ACK timer (< 500ms)

### Module 7: Send Path
- Segmentation (split app data into MSS-sized segments)
- Nagle algorithm (coalesce small writes)
- SWS avoidance (sender side)
- Send window management
- PSH flag logic
- Urgent pointer management
- Retransmission queue management

### Module 8: Receive Path
- Segment acceptability testing
- In-order delivery to application
- Out-of-order segment queuing (SHLD-31)
- Reassembly
- Window advertisement (SWS avoidance, receiver side)
- Delayed ACK logic
- Urgent data notification

### Module 9: Congestion Control
- Slow start / congestion avoidance (RFC 5681)
- Fast retransmit / fast recovery
- RTO exponential backoff (RFC 6298)
- ECN support (RFC 3168, SHLD-8)
- cwnd, ssthresh management

### Module 10: Connection Table
- TCB lookup by 4-tuple
- LISTEN socket management (wildcard matching)
- TIME-WAIT bucket management
- Port allocation

### Module 11: ICMP Integration
- Map ICMP errors to connections
- Soft vs hard error classification
- PMTUD integration

### Module 12: Application Interface (Socket API)
- OPEN (listen/connect)
- SEND (write)
- RECEIVE (read)
- CLOSE (shutdown/close)
- ABORT (RST)
- STATUS
- Socket options: TCP_NODELAY, SO_KEEPALIVE, timeouts, MSS, DSCP

---

## 19. Compliance Requirement Summary (Key MUST Items)

| ID | Requirement |
|----|-------------|
| MUST-1 | Window treated as unsigned |
| MUST-2 | Sender computes checksum |
| MUST-3 | Receiver verifies checksum |
| MUST-4 | Support mandatory options (EOL, NOP, MSS) |
| MUST-5 | Accept options in any segment |
| MUST-6 | Ignore unknown options |
| MUST-7 | Handle illegal option lengths |
| MUST-8 | Clock-driven ISN selection |
| MUST-9 | ISN PRF not externally computable |
| MUST-10 | Support simultaneous open |
| MUST-11 | Track passive vs active origin of SYN-RECEIVED |
| MUST-12 | Inform app of normal close vs abort |
| MUST-13 | TIME-WAIT = 2*MSL |
| MUST-14 | Implement MSS option send + receive |
| MUST-15 | Default send MSS: 536 (IPv4), 1220 (IPv6) |
| MUST-16 | Calculate effective send MSS |
| MUST-17 | Allow disabling Nagle per connection |
| MUST-18 | RFC 6298 RTO computation with Karn's algorithm |
| MUST-19 | Implement slow start, congestion avoidance, exponential backoff |
| MUST-20 | R1/R2 retransmission failure thresholds |
| MUST-21 | Application must be able to set R2 |
| MUST-22 | Same R1/R2 mechanism for SYN retransmissions |
| MUST-23 | SYN R2 >= 3 minutes |
| MUST-24..29 | Keep-alive rules (if implemented) |
| MUST-30 | Support urgent mechanism |
| MUST-34 | Robust against window shrinking |
| MUST-35..37 | Zero-window probing |
| MUST-38..39 | SWS avoidance (sender + receiver) |
| MUST-40 | Delayed ACK < 500ms |
| MUST-41 | Passive OPEN doesn't affect existing connections |
| MUST-42 | Concurrent LISTEN on same port |
| MUST-43 | Support local IP address parameter in OPEN |
| MUST-44 | Ask IP for source address for SYN if not specified |
| MUST-45 | Use same local address for all segments on a connection |
| MUST-46 | Reject OPEN to broadcast/multicast |
| MUST-47 | Error reporting to application |
| MUST-48 | Application can specify DSCP for outgoing segments |
| MUST-49 | Configurable TTL |
| MUST-50 | Ignore unknown IP options |
| MUST-51 | Application can specify source route on active open |
| MUST-52 | Source route takes precedence |
| MUST-53 | Save and use return route on passive open |
| MUST-54..57 | ICMP handling |
| MUST-58..59 | ACK aggregation |
| MUST-60..62 | PUSH and urgent pointer semantics |
| MUST-63 | Reject segments with invalid source address |
| MUST-64 | Process options regardless of word alignment |
| MUST-65 | MSS option only in SYN segments |
| MUST-66 | Process RST and URG even when RCV.WND is zero |
| MUST-67 | MSS value to send based on MMS_R |
| MUST-68 | All options except EOL/NOP must have length fields |
| MUST-69 | Padding after options must be zeros |

### Key SHOULD Items

| ID | Requirement |
|----|-------------|
| SHLD-1 | Use PRF-based ISN generation formula |
| SHLD-2 | RST may contain data |
| SHLD-3 | Send RST if data lost on half-duplex close |
| SHLD-4 | Use Timestamps to reduce TIME-WAIT |
| SHLD-5 | Send MSS option when receive MSS differs from default |
| SHLD-6 | Use smallest effective MTU for variable-MTU interfaces |
| SHLD-7 | Implement Nagle algorithm |
| SHLD-8 | Implement ECN (RFC 3168) |
| SHLD-9 | Inform application between R1 and R2 |
| SHLD-10 | R1 >= 3 retransmissions |
| SHLD-11 | R2 >= 100 seconds |
| SHLD-12 | Keep-alive probe with no data |
| SHLD-13 | New applications SHOULD NOT use urgent mechanism |
| SHLD-14 | Receiver SHOULD NOT shrink window |
| SHLD-15..17 | Window shrinking sender behavior |
| SHLD-18 | Implement delayed ACKs |
| SHLD-19 | ACK at least every 2nd full-sized segment |
| SHLD-20 | Application can disable error reports |
| SHLD-21..23 | Diffserv field behavior |
| SHLD-24 | Later source route overrides earlier |
| SHLD-25..26 | ICMP soft/hard error handling |
| SHLD-27 | Collapse successive PSH bits |
| SHLD-28 | Send maximum-sized segments |
| SHLD-29..30 | Zero-window probe timing |
| SHLD-31 | Hold out-of-order segments for later processing |

### Key MAY Items

| ID | Requirement |
|----|-------------|
| MAY-1 | Half-duplex close |
| MAY-2 | Accept SYN from TIME-WAIT |
| MAY-3 | Always send MSS option |
| MAY-4 | Retransmit with same IPv4 Identification |
| MAY-5 | Implement keep-alives |
| MAY-6 | Keep-alive with garbage octet |
| MAY-7 | Retransmit old data beyond SND.UNA+SND.WND |
| MAY-8 | Receiver keeps window closed indefinitely |
| MAY-9 | Pass received Diffserv field to application |
| MAY-10 | Support IP Timestamp option |
| MAY-11 | Support IP Record Route option |
| MAY-12 | RFC 5961 ACK validation (blind data injection protection) |
| MAY-13 | Send ACK for valid out-of-order segments |
| MAY-14 | FLUSH call implementation |
| MAY-15 | Implement PUSH flags on SEND calls |
| MAY-16 | Aggregate un-pushed data internally |
| MAY-17 | Pass received PSH to application |
| MAY-18 | Implement alternative conformant congestion control |

### Recommendation

| ID | Requirement |
|----|-------------|
| REC-1 | Use 32-bit fields for send/receive window sizes internally |

---

## 20. Constants and Defaults

| Constant | Value | Notes |
|----------|-------|-------|
| MSL | 2 minutes | Maximum Segment Lifetime |
| TIME-WAIT duration | 4 minutes | 2 * MSL |
| Default IPv4 MSS | 536 | 576 - 40 |
| Default IPv6 MSS | 1220 | 1280 - 60 |
| Min TCP header | 20 bytes | 5 * 32-bit words |
| Max TCP header | 60 bytes | 15 * 32-bit words (40 bytes of options) |
| Initial RTO | 1 second | Per RFC 6298 |
| Min RTO | 1 second | Per RFC 6298 |
| Delayed ACK max | < 500ms | MUST-40 (500ms itself is forbidden) |
| Keep-alive default interval | >= 2 hours | MUST-28 |
| SYN retry timeout (R2) | >= 3 minutes | MUST-23 |
| R1 threshold | >= 3 retransmissions | SHLD-10 |
| R2 threshold | >= 100 seconds | SHLD-11 |
| SWS fraction (Fs) | 1/2 | Recommended |
| SWS receiver fraction (Fr) | 1/2 | Recommended |
| SWS override timeout | 0.1 - 1.0 seconds | Recommended |
| Protocol number | 6 | For pseudo-header |

---

## 21. Implementation Notes (from RFC Appendices)

### IP Security Compartment and Precedence

References to IP "security/compartment" in segment processing (e.g., Section 16 Steps 3-4) are relevant for Multi-Level Secure (MLS) systems but can be ignored for non-MLS implementations. The old IPv4 TOS precedence processing from RFC 793 is obsolete — replaced by Differentiated Services. TCP implementations SHOULD NOT include the old TOS precedence logic; Diffserv is asymmetric per-direction, and the old symmetric precedence matching was deprecated by RFC 2873.

### Sequence Number Validation Edge Cases

There are edge cases where TCP sequence number validation rules can prevent ACK fields from being processed, causing connection issues in scenarios including: simultaneous open, self-connects, simultaneous close, and simultaneous window probes. In Internet usage these rarely occur, and common OSes include varying mitigations. Implementers should be aware of these edge cases (described in draft-gont-tcpm-tcp-seq-validation).

### Low Watermark Settings

Some OS kernel TCP implementations include socket options for controlling buffer thresholds:
- **SO_SNDLOWAT**: Bytes in buffer before the socket layer passes data to TCP
- **SO_RCVLOWAT**: Bytes in buffer before data is passed to the application
- **TCP_NOTSENT_LOWAT**: Controls amount of unsent bytes in the write queue, useful for applications multiplexing multiple streams (e.g., mix of interactive and bulk data) to limit buffered latency
