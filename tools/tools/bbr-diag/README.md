# bbr-diag

Records what FreeBSD's `tcp_bbr` stack is doing when a connection stops making progress: the stack's own state from DTrace probes, a packet capture of the same connection, and the TCP counters before and after, packed in one file.

It needs a kernel whose `tcp_bbr` module carries the `bbr` DTrace provider. That provider is added by the commit "tcp bbr: DTrace probes for a connection that stops sending" on this branch. Both are test instrumentation, not for upstream, and assume a 64-bit kernel.

| File | What it is |
|---|---|
| `bbr-diag.sh` | Runs on the sending host: checks, counters before and after, tcpdump, the DTrace trace, one tarball. |
| `tests/smoke.sh` | Exercises `bbr-diag.sh` with stand-ins for the FreeBSD commands. |

## What is and is not verified

The probes and the script have run on FreeBSD 15.2-STABLE (amd64, GENERIC, kernel and userland from the same tree): the check, a dry run, and a ten-minute run that recorded four stalls.

| Part | Checked | Not checked |
|---|---|---|
| Kernel patch | Built, loaded and traced on 15.2-STABLE. In a container: clang 21.1.8 (the tree's version) with the option headers of GENERIC, syntax and object, no warning; with the probes compiled out the object is the untouched file's, byte for byte | Other architectures. The packed arguments assume 64 bits. |
| D program | Compiles and runs on 15.2-STABLE; the snapshot the kernel fills and the one the script declares agree | `-r` and `-L` on a real kernel. |
| `bbr-diag.sh` | 58 checks in a container against stand-ins; one real run | Pruning on a real run. The first real run lost its capture to it, for a reason that was not found. The script now removes nothing unless its list of stalls matches the trace, and says in `prune.txt` what it removes. |
| A kernel and a userland from different branches | | Do not use a kernel older than its userland: rc starts no service there, and `netstat -s` puts the kernel's TCP counters under the wrong labels. |
| Probe cost | Estimated from the DTrace code: about 0.1 µs per firing, about five firings per ACK and per send, a few percent of one core at 100,000 packets a second | Not measured. If the stall stops reproducing, use `-L`. |
| Stall detection | Found four real stalls of 1.2 s to 155 s | The thresholds are guesses: under 1 Mbit/s acknowledged for 1 s. |

## The kernel

Build and install the kernel of this branch as usual (`make buildkernel`, `make installkernel`), then:

```sh
kldload tcp_bbr 2>/dev/null; kldstat -m tcp_bbr
dtrace -x nolibs -l -P bbr | wc -l         # 24: a header and 23 probes
```

The commit "tcp bbr: test switch for the sending-rate gate of a b/w sample" adds `net.inet.tcp.bbr.measure.sendrate_gate`. A bandwidth sample is the delivery rate, lowered to a sending rate when that is smaller: the bytes in flight at the send, divided by the time since the earliest outstanding send. With 0 the stack does that as before. With 1 the earliest send is the first one not marked lost, since what is marked lost is not counted in the flight either. With 2 a sample is never lowered to the sending rate. A change takes effect with the next segment sent, and the run's `sysctl-bbr-before.txt` records the value.

When a later commit changes only `bbr.c`, the same `buildkernel` rebuilds just the module. Build the module with `buildkernel`, not with `make` in `sys/modules/tcp/bbr`: on its own it is compiled without `KDTRACE_HOOKS` and has no probes. Copy the new `tcp_bbr.ko` from the object tree into the kernel's directory and reboot. Swapping the module without a reboot (`kldunload tcp_bbr; kldload tcp_bbr`) works only when no connection uses the BBR stack, the SSH session included, and it resets every `net.inet.tcp.bbr` sysctl to its default.

## Run it

All as root.

1. **Check, a few seconds, no traffic needed:**
   ```sh
   sh bbr-diag.sh -C
   ```
   It says which step failed and leaves the details in `/var/tmp/bbr-diag-<date>/check.txt`.

2. **Dry run, 30 seconds, with any iperf3 traffic:**
   ```sh
   sh bbr-diag.sh -d 30 -n 0
   ```
   A good run prints no error, and its `trace.txt` holds a `LAYOUT` line with `size=232 expect=232`, `STATE` lines ten times a second, and `TICK` lines with `live=1` once the transfer is under way. `LAYOUT-MISMATCH` means the script and the kernel are from different commits. `live=0` throughout means the detector never recognised the data connection, so it cannot report a stall.

3. **The real run**, with the sysctls that reproduce the stall set first:
   ```sh
   sh bbr-diag.sh -c <client address>
   ```
   Start iperf3 when it says so. It prints a line when a stall begins and ends, stops by itself after three stalls (`-n`), and writes the tarball inside its folder.

| Option | Meaning | Default |
|---|---|---|
| `-p port` | Trace connections with this local or remote port | 5201 |
| `-c address` | Capture only packets to and from this address | all on the port |
| `-i interface` | Capture interface | the route's |
| `-d seconds` | Stop after this long | until Enter |
| `-n stalls` | Stop once this many stalls are recorded; 0 for no limit | 3 |
| `-s ms`, `-g kbit` | A stall is this long under this acknowledged rate | 1000, 1000 |
| `-a seconds` | Capture kept before and after each stall | 20 |
| `-M MiB` | Stop when the folder reaches this size | 4096 |
| `-k` | Keep the whole capture | off |
| `-L` | Light trace: no per-packet probes | off |
| `-r` | Also keep a per-CPU ring of every event, written out when a stall begins | off |
| `-H command` | Run this each time a stall is recorded | none |
| `-C` | Check only | off |

- `-L` keeps the rare events, the state line and stall detection. During a stall it prints one line per received segment and cannot say why an output call sent nothing.
- `-r` roughly doubles the per-packet cost and is the only way to get per-packet history from before a stall.
- The detector follows one data connection at a time: with several parallel streams it reports a stall only when the one it happens to sample stalls.
- The capture is headers only (`-s 128`) in ten-second files, and all of it is kept until the folder holds a quarter of `-M`. From then on only the files within `-a` seconds of a stall stay, plus the last two as a sample; `prune.txt` lists every file removed, and every pass that removed nothing because its list of stalls did not match the trace. On the sender tcpdump sees segments before TSO splits them, so lengths above the MSS are normal there.
- The kernel caps tcpdump's buffer at `net.bpf.maxbufsize` (512 KiB by default). The script reports lost packets at the end; raise that sysctl if it does.

## On the receiving host

Start these before the sender's real run. The ring holds about 8 GB; size `-W` to the disk.

```sh
# capture ring: 8 files of 1 GB, headers only
sudo tcpdump -i en0 -s 128 -C 1000 -W 8 -w /var/tmp/bbr-client.pcap \
    'tcp port 5201 and host <sender address>'

# in another terminal: the sender sends, one line a second with the time
iperf3 -c <sender address> -p 5201 -R -t 0 -i 1 --forceflush \
    --timestamps='%F %T ' --logfile ~/bbr-client-iperf3.txt
tail -f ~/bbr-client-iperf3.txt
```

When iperf3 shows `0.00 bits/sec`, or the sender prints `stall N began`, let it run about 20 seconds past the stall, then stop tcpdump with Ctrl-C before the ring wraps (about eight minutes at full rate). Keep the `bbr-client.pcap*` files written around the stall and `bbr-client-iperf3.txt`.

To stop that capture without watching, give the sender's `-H` a command that does it, for example `-H "ssh user@client 'sudo pkill -INT tcpdump'"`.

**Lining the three up.** The trace and the sender's capture share one clock. Trace lines carry `ts` (DTrace's nanosecond clock); `TICK` lines also carry `wall` (nanoseconds since 1970, only as fine as the kernel tick, 10 ms on a VM). Every `send` event carries the raw sequence number and length, which pins `ts` to the capture's timestamps exactly. The two captures line up by raw sequence number, so the two hosts' clocks need not agree.

## What the run writes

| File | Content |
|---|---|
| `trace.txt` | The trace, one event per line |
| `trace.err` | DTrace's own messages, if any (drops, errors) |
| `pcap/srv-<epoch>.pcap` | Capture files, named by the second they start |
| `netstat-tcp-{before,after}.txt` | `netstat -s -p tcp`: ghost ACKs, ACKs too old, timeouts |
| `sysctl-bbr-{before,after}.txt` | `net.inet.tcp.bbr`, settings and the stack's counters |
| `sysctl-pacer-*`, `netstat-m-*`, `netstat-if-*`, `vmstat-z-*` | Pacer, mbuf, interface and zone counters |
| `system.txt`, `check.txt`, `notes.txt`, `times.txt` | Kernel, settings, the checks, remarks, start and end |
| `bbr-run.d` | The D program as run |
| `prune.txt` | Only if capture files were removed: which, and when |
| `ring-N.txt` | With `-r`: every event up to the start of stall N |
| `<folder name>.tar.gz` | All of the above: the file to send |

No hostname is written, and the text files hold no address. The capture holds both hosts' addresses.

### Lines of `trace.txt`

Lines come out grouped per CPU, not in time order: sort on `ts=` before reading.

| Line | When | Fields |
|---|---|---|
| `BEGIN` | Start | The settings |
| `LAYOUT` | First event of any BBR connection | Snapshot size the kernel fills and the size the script expects |
| `STATE` | First received segment after each 100 ms | The snapshot |
| `TICK` | Every 100 ms | `step` 1 under the floor, 2 over, 0 nothing to judge; `quiet`, `moving` steps in a row; `live` 1 while the data connection is established; lines left in each budget |
| `EV <probe>` | A rare event, or any event during a stall | `a2`..`a5`, then the snapshot |
| `HPTS` | After `EV timer-start` during a stall | What the pacer reported at insertion |
| `XEV` | Base kernel probes, all connections | TCP state changes, `tcp_drop` with its errno, segments dropped by the shared helpers |
| `COUNTS`, `NOSEND`, `FASTACK` | Every second | Output calls that sent nothing, and ACKs that left the fast path, by reason |
| `STALL-BEGIN`, `STALL-END` | Detector | `quiet` says how many steps back the stall began; `flight` and `sb` say whether data was waiting |

- `tp` is the tcpcb address and names the connection; `lp`/`fp` are its ports.
- The detector counts any second without progress on the data connection, also when the application had nothing to send. `flight=0 sb=0` on `STALL-BEGIN` is that case.
- Per 100 ms at most 100 rare events, 50 retransmissions, 50 base-kernel lines and 300 stall events print. A `TICK` with a budget at 0 means lines were dropped.
- `conn-init` prints for every new BBR connection, with ports 0: BBR attaches before the ports are assigned. Match it to the connection by `tp`. `rtt-shrinks`, `state-change` and `timer-start` of the setup fire before it.

**Snapshot fields.**

| Fields | Meaning |
|---|---|
| `cts` | The stack's microsecond clock; wraps every 71 minutes |
| `una max nxt iss` | Sequence space |
| `wnd mxw hirw cwnd tgt` | Peer window, largest seen, highest advertised, cwnd, flight target of the BBR state |
| `flight sb` | Bytes in flight as the stack counts them; bytes in the send buffer |
| `sacked lostb holes maps` | Scoreboard: SACKed, marked lost, retransmitted and outstanding, entries |
| `lost deliv appl` | Running totals of lost and delivered bytes; application-limited mark |
| `bw bwcur bwlt` | Bytes/s: the filter, the last sample, the policer estimate |
| `rttp srtt lrtt rxtcur` | µs: minimum RTT filter, smoothed, last, current retransmit value |
| `rxtshift hf texp` | Backoff count; what is pending (bits below); when it expires on the `cts` clock |
| `pstart delay aggd agge` | Pacer start time, pacing delay, pacing debt and credit |
| `pmax pmin mss` | Segment sizes |
| `rcvt stt rtts prtti prtte pe` | Times of last input, state entry, last RTT drop; probe-RTT interval and entry; packet epoch |
| `tstate st sub pgain cgain` | TCP state (4 established); BBR state and gain-cycle step; gains in 1/256 |
| `per rec hpts tfirst` | Persist, recovery, on the pacer wheel, timer ahead of paced output |
| `tstop allstop tovr want cwl coll rs` | Stopped timers, timer override, output wanted, cwnd limited, peer window collapsed, a retransmission is queued |
| `tlps tlpip tlpro tlpnd tlpc` | Tail loss probe state |
| `ltu lts goog fill nopace` | Policer rate in use, sampling; Google mode, pipe filled, pacing off |
| `oerr oerrs pcons recbw tsrc piw pir` | Output errors, recovery modes, timer source, past initial window |
| `fl fl2 lp fp` | `t_flags`, `t_flags2`, local and remote port |

`hf` bits: 0x01 delayed ACK, 0x02 RACK, 0x04 tail loss probe, 0x08 retransmit, 0x10 persist, 0x20 keepalive, 0x40 paced output. `st`: 1 startup, 2 drain, 3 probe-BW, 4 probe-RTT, 5 idle exit; `sub` 0 is the 1.25 gain step, 1 the 0.75 step.

### The probes and their values

A "line" is a source line of the patched `bbr.c`; it says which caller it was.

| Probe | Fires | a2 | a3 | a4 | a5 |
|---|---|---|---|---|---|
| `input` | A segment enters the stack | seq | ack | window | bits: 0-31 length, 32-43 TCP flags, 44 SACK present, 45 more queued, 48-63 segments merged by LRO |
| `input-done` | It has been processed | more queued | output was called | | |
| `input-drop` | It was rejected | reason | ack | lowest ack accepted | seq |
| `fastack-bail` | An ACK left the fast path | reason | ack | window | |
| `output` | `bbr_output_wtime` is entered | called by the pacer | | | |
| `nosend` | It returns without sending | reason | called by the pacer | reason 3: the timer handler's return; else the stack's own class, 1 cwnd, 2 rwnd, 3 application | high half bytes sent earlier in the call, low half length held back |
| `send` | A segment was handed to IP, or failed | seq, 0 if it failed | length | errno | bits: 0-11 TCP flags, 16 retransmission, 17 tail loss probe, 18 from the scoreboard, 19 TSO, 20 called by the pacer, 21 persist |
| `output-error` | A send failed: in `ip_output`, for want of an mbuf, or before a header was built | errno | errors in a row | length | |
| `timer-start` | A timer or pacing slot was set | caller | pacing delay µs | timer µs | pacer details |
| `timer-busy` | Nothing set: already on the pacer | caller | delay asked | | |
| `timer-cancel` | A pending timer was cancelled | line | taken off the pacer | | |
| `timer-check` | Timers were looked at | result | timers due, or µs left for -3 | called by the pacer | |
| `timeout` | A timer acted | which | | | |
| `persist` | Persist entered or left | 1 enter, 0 exit | line | µs spent | |
| `state-change` | BBR state or gain step changed | line | | | |
| `rtt-shrinks` | Minimum RTT or probe-RTT event | reason | line | | |
| `cwnd` | cwnd was set | rule | target | line | bytes acked |
| `rwnd-collapse` | Peer window below what is outstanding | step | edge seq | count | |
| `lt-bw` | Policer detection | reason | new rate | old rate | µs |
| `recovery-enter`, `recovery-exit` | Loss recovery | seq | | | |
| `conn-init`, `conn-fini` | BBR attached to or left a connection | | | | |

| Value | Meanings |
|---|---|
| `nosend` reason | 0 no rule held data back: see `wnd`, `cwnd`, `flight`, `sb`; with a length above 0 it was silly-window avoidance. 1 a timer is pending and nothing is new. 2 paced output not yet due. 3 a timer handler ended the call. 4 fast open handshake. 5 no memory for a send map entry. 6 send map limit. 7 less than a pacing segment while data is in flight. 8 peer window under a pacing segment. 9 cwnd leaves less than the minimum segment. 10 peer window filled. 11 persist and the window still small. 12 FIN held behind data. |
| `input-drop` reason | 1 ghost ACK. 2 ACK too old. 3 ACK above `snd_max`. 4 timestamp missing. 5 SYN with FIN. |
| `fastack-bail` reason | 1 old or duplicate ACK. 2 above `snd_max`. 3 zero window. 4 SYN or FIN needed. 5 timestamp behind. 6 in recovery. 7 retransmission queued. 8 persist. 9 SACKed data on the scoreboard. |
| `timeout` | 1 retransmit. 2 tail loss probe. 3 RACK. 4 keepalive. 5 persist. 6 delayed ACK. |
| `timer-check` result | -1 paced output pending and the timer not due. -2 not the pacer calling and not due. -3 the pacer called early and the connection was put back. 0 handled and output continues. 1 the handler finished the call. A negative errno: the connection is being dropped. |
| `timer-start` caller | 1 timer audit after input. 3 persist timeout. 4 keepalive timeout. 5 connection setup. 6 input that needed no output. 8 input that found no timer. 9 a no-send return. 10 EMSGSIZE. 11 another output error. 12 after a send. Both a3 and a4 at 0: nothing was set at all. |
| `cwnd` rule | 1 packet conservation. 2 toward the target. 3 startup growth. 4 startup at target. 10 limit against the target. 12 clamp or restore for drain and probe-RTT. 13 undo after a spurious timeout. 14 recovery entered. 15, 16 recovery left. 21, 22 reduction after recovery. |
| `lt-bw` reason | 0 policer rate no longer used. 1 sampling begins. 2, 3 sampling reset. 4 policed: the long-term rate is in use. 5 first sample kept. 6 not yet. 7, 8 false-positive check. |
| `rtt-shrinks` reason | 0 setup. 1 new minimum. 2 probe-RTT left. 3 was idle. 4 persist counted as a probe. 5 probe-RTT target reached. 6 probe-RTT entered. 7, 8 gain lowered. 9 new target. 10 drain left. 11 interval reset. |
| `rwnd-collapse` step | 1 check begins. 3 an entry was split. 4 entries marked. 0 window recovered. |

Three exits of `bbr_output_wtime` fire neither `nosend` nor `send`. TCP offload fires nothing. The two sends dropped before a header is built (the UDP tunnel port is gone; the send map and the send buffer disagree, which drops the connection) fire `output-error` only.
