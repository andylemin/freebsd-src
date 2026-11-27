#!/bin/sh
#
# Exercise bbr-diag.sh with stand-ins for the FreeBSD commands it runs:
# its options, its checks and their messages, the run loop, the pruning of
# the capture and the package. It does not run DTrace, tcpdump or a
# FreeBSD kernel, so it says nothing about the D program or the probes.
#
# usage: smoke.sh /path/to/bbr-diag.sh [folder]
#
# Run as root in a throwaway container: it writes only below a folder it
# makes in /tmp, and copies the D programs to "folder" when one is given.

set -u

script=$1
work=$(mktemp -d /tmp/bbrdiag-smoke.XXXXXX)
stubs=$work/stubs
mkdir "$stubs"

# ---- the stand-ins ----

cat > "$stubs/uname" << 'EOF'
#!/bin/sh
case "$*" in
    -s) echo FreeBSD ;;
    -srm) echo "FreeBSD 15.2-STABLE amd64" ;;
    -v) echo "FreeBSD 15.2-STABLE #0 stable/15-n287016-0123456789ab: Fri Nov 27 03:00:00 UTC 2026     root@buildhost.example:/usr/obj/usr/src-stable15/amd64.amd64/sys/GENERIC" ;;
    *) echo FreeBSD ;;
esac
EOF

cat > "$stubs/kldstat" << 'EOF'
#!/bin/sh
if [ "${1:-}" = -q ]; then
    [ "${STUB_NO_BBR:-0}" = 1 ] && [ "$3" = tcp_bbr ] && exit 1
    exit 0
fi
echo "Id Refs Address                Size Name"
echo " 1   40 0xffffffff80200000  1f3e2a8 kernel"
echo " 5    1 0xffffffff82a00000    2f000 tcp_bbr.ko"
EOF

cat > "$stubs/kldload" << 'EOF'
#!/bin/sh
exit 0
EOF

cat > "$stubs/freebsd-version" << 'EOF'
#!/bin/sh
echo "15.2-STABLE"
echo "16.0-CURRENT"
EOF

cat > "$stubs/sysctl" << 'EOF'
#!/bin/sh
for n; do
    echo "$n: 1"
done
EOF

cat > "$stubs/vmstat" << 'EOF'
#!/bin/sh
echo "ITEM                   SIZE     LIMIT     USED     FREE      REQ FAIL SLEEP XDOM"
EOF

cat > "$stubs/route" << 'EOF'
#!/bin/sh
echo "   route to: default"
echo "  interface: mce0"
EOF

cat > "$stubs/ifconfig" << 'EOF'
#!/bin/sh
echo "$1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500"
echo "	options=ed07bb<RXCSUM,TXCSUM,TSO4,TSO6,LRO>"
echo "	ether 02:00:00:aa:bb:cc"
echo "	inet 192.0.2.27 netmask 0xffffff00 broadcast 192.0.2.255"
echo "	media: Ethernet autoselect <full-duplex>"
echo "	status: active"
EOF

cat > "$stubs/netstat" << 'EOF'
#!/bin/sh
case "$*" in
    *-I*)
        echo "Name    Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll  Drop"
        echo "mce0   1500 <Link#1>      02:00:00:aa:bb:cc     1000     0     0    1000000     2000     0    2000000     0     0"
        echo "mce0      - 192.0.2.0/24  192.0.2.27            1000     -     -    1000000     2000     -    2000000     -     -"
        ;;
    *-m*) echo "1024/2048/3072 mbufs in use (current/cache/total)" ;;
    *) echo "tcp:"
       echo "	12 ACKs dropped due to ghost ACK"
       ;;
esac
EOF

# Every way bbr-diag.sh calls dtrace: -l to list probes, -e to compile,
# and a run that writes a trace with one stall and stops on SIGTERM.
cat > "$stubs/dtrace" << 'EOF'
#!/bin/sh
echo "$*" >> "${STUB_LOG:-/dev/null}"
[ "${STUB_DTRACE_BROKEN:-0}" = 1 ] && {
    echo "dtrace: failed to initialize dtrace: Bad address" >&2
    exit 1
}
mode=run
script=
out=
prov=
while [ $# -gt 0 ]; do
    case $1 in
        -x) shift ;;
        -q) ;;
        -l) mode=list ;;
        -e) mode=compile ;;
        -n) shift ;;
        -P) prov=$2; shift ;;
        -s) script=$2; shift ;;
        -o) out=$2; shift ;;
        *) ;;
    esac
    shift
done
all="conn-init conn-fini input input-done input-drop fastack-bail output
nosend send output-error timer-start timer-busy timer-cancel timer-check
timeout persist state-change rtt-shrinks cwnd rwnd-collapse lt-bw
recovery-enter recovery-exit"
case $mode in
    list)
        echo "   ID   PROVIDER            MODULE                          FUNCTION NAME"
        if [ -n "$prov" ]; then
            [ "${STUB_NO_PROBES:-0}" = 1 ] && exit 0
            for p in $all; do
                [ "${STUB_FEW_PROBES:-0}" = 1 ] && [ "$p" = nosend ] && continue
                [ "${STUB_FEW_PROBES:-0}" = 1 ] && [ "$p" = lt-bw ] && continue
                echo "86754        bbr           tcp_bbr                              none $p"
            done
        else
            echo "12345        fbt            kernel                   some_function entry"
        fi
        ;;
    compile)
        [ -r "$script" ] || exit 1
        case ${STUB_COMPILE_FAIL:-} in
            all)
                echo "dtrace: failed to compile script $script: line 7: syntax error near \"int\"" >&2
                exit 1
                ;;
            extras)
                if grep -q '^fbt:' "$script"; then
                    echo "dtrace: failed to compile script $script: line 400: probe description fbt::tcp_drop:entry does not match any probes" >&2
                    exit 1
                fi
                ;;
            *) ;;
        esac
        ;;
    run)
        [ -n "$script" ] || exit 0
        case $out in
            */ring-*)
                trap 'echo "R send ts=1 tp=ffff a2=1" >> "$out"; exit 0' TERM
                while :; do sleep 1; done
                ;;
            *) ;;
        esac
        trap 'echo "END ts=9 wall=9 stalls=1" >> "$out"; exit 0' TERM
        echo "BEGIN ts=1 wall=1 port=5201" >> "$out"
        if [ "${STUB_MISMATCH:-0}" = 1 ]; then
            echo "LAYOUT ts=2 magic=0 size=1 expect=232 version=0" >> "$out"
            echo "LAYOUT-MISMATCH the kernel's snapshot is not the one this script declares" >> "$out"
            exit 3
        fi
        if [ "${STUB_NO_CONN:-0}" != 1 ]; then
            echo "LAYOUT ts=2 magic=42425253 size=232 expect=232 version=1" >> "$out"
            echo "STATE ts=3 tp=fffff80012345000 cts=1 una=1000" >> "$out"
        fi
        i=0
        at=${STUB_STALL_AT:-4}
        while :; do
            sleep 1
            i=$((i + 1))
            [ "${STUB_NO_CONN:-0}" = 1 ] && continue
            if [ "$i" -eq "$at" ]; then
                # a stall line with no end, which the list of stalls drops
                [ "${STUB_DOUBLE_BEGIN:-0}" = 1 ] && echo "STALL-BEGIN id=0 ts=3 wall=$(date +%s)000000000 tp=fffff80012345000 una=900 quiet=10" >> "$out"
                echo "STALL-BEGIN id=1 ts=4 wall=$(date +%s)000000000 tp=fffff80012345000 una=1000 quiet=10" >> "$out"
            fi
            if [ "$i" -eq $((at + 3)) ]; then
                echo "STALL-END id=1 ts=7 wall=$(date +%s)000000000 ms=3000 live=1" >> "$out"
            fi
        done
        ;;
esac
exit 0
EOF

# A new capture file each second, named as tcpdump -G names them.
cat > "$stubs/tcpdump" << 'EOF'
#!/bin/sh
pat=
while [ $# -gt 0 ]; do
    case $1 in
        -w) pat=$2; shift ;;
        *) ;;
    esac
    shift
done
trap 'echo "7 packets dropped by kernel" >&2; exit 0' TERM
while :; do
    echo data > "$(echo "$pat" | sed "s/%s/$(date +%s)/")"
    sleep 1
done
EOF
chmod +x "$stubs"/*

PATH=$stubs:$PATH
export PATH

# ---- the cases ----

fail=0
n=0
check() {
    n=$((n + 1))
    desc=$1
    shift
    if "$@" > /dev/null 2>&1; then
        echo "ok $n - $desc"
    else
        echo "not ok $n - $desc"
        fail=1
    fi
}
# run name [VAR=value ...] -- arguments: bbr-diag.sh with these stand-in
# switches; its output goes to $work/name.out and its status to $rc
run() {
    name=$1
    shift
    env=
    while [ "$1" != -- ]; do
        env="$env $1"
        shift
    done
    shift
    # shellcheck disable=SC2086
    env $env STUB_LOG="$work/$name.calls" sh "$script" "$@" \
        > "$work/$name.out" 2>&1 < /dev/null
    rc=$?
}
has() {
    grep -q -e "$2" "$1"
}
lacks() {
    ! grep -q -e "$2" "$1"
}

run check -- -C -o "$work/check"
check "a check on a good system passes" [ "$rc" -eq 0 ]
check "and says so" has "$work/check.out" 'every check passed'
check "the trace script is written" [ -s "$work/check/bbr-run.d" ]
check "with the base kernel's probes" has "$work/check/bbr-run.d" '^fbt::tcp_drop:entry'
check "with five macro arguments" has "$work/check.calls" ' 5201 10 12500 300 5$'
check "the check starts no capture" lacks "$work/check.out" 'capturing'

run light -- -C -L -o "$work/light"
check "a light trace leaves out the per-packet probes" lacks "$work/light/bbr-run.d" '^bbr:::nosend'
check "and keeps the state line" has "$work/light/bbr-run.d" '^bbr:::input-done'

run broken STUB_DTRACE_BROKEN=1 -- -C -o "$work/broken"
check "a DTrace that does not run fails the check" [ "$rc" -eq 1 ]
check "with its reason" has "$work/broken.out" 'DTrace does not run on this kernel'

run nobbr STUB_NO_BBR=1 -- -C -o "$work/nobbr"
check "a missing tcp_bbr module fails the check" has "$work/nobbr.out" 'tcp_bbr module is not loaded'

run noprobes STUB_NO_PROBES=1 -- -C -o "$work/noprobes"
check "a module without the probes fails the check" [ "$rc" -eq 1 ]
check "and names the kernel" has "$work/noprobes.out" 'has no bbr probes.*stable/15-n287016'
check "without the build host" lacks "$work/noprobes.out" 'buildhost'

run fewprobes STUB_FEW_PROBES=1 -- -C -o "$work/fewprobes"
check "missing probes are named" has "$work/fewprobes.out" 'lacks these probes: *nosend lt-bw'

run noextras STUB_COMPILE_FAIL=extras -- -C -o "$work/noextras"
check "the base kernel's probes are left out when they fail" [ "$rc" -eq 0 ]
check "and the script says so" has "$work/noextras.out" 'left out'
check "and runs without them" lacks "$work/noextras/bbr-run.d" '^fbt:'

run nocompile STUB_COMPILE_FAIL=all -- -C -o "$work/nocompile"
check "a script that does not compile fails the check" [ "$rc" -eq 1 ]
check "with the compiler's message" has "$work/nocompile.out" 'syntax error near'

run badport -- -p http -o "$work/badport"
check "a port that is no number is refused" [ "$rc" -eq 2 ]
run both -- -L -r -o "$work/both"
check "-L with -r is refused" has "$work/both.out" 'give one of them'
run notty -- -o "$work/notty"
check "no terminal and no -d is refused" has "$work/notty.out" 'give -d'
mkdir "$work/exists"
run exists -- -d 5 -o "$work/exists"
check "an existing folder is refused" has "$work/exists.out" 'exists; give -o'

run mismatch STUB_MISMATCH=1 -- -d 20 -n 0 -o "$work/mismatch"
check "a layout mismatch fails the run" [ "$rc" -eq 1 ]
check "and explains it" has "$work/mismatch.out" 'snapshot and this script'

run noconn STUB_NO_CONN=1 -- -d 6 -n 0 -o "$work/noconn"
check "a run that saw no connection says so" has "$work/noconn.out" 'no connection on port 5201'

# one stall at about second 12 to 15 of a 40 second run; files are a
# second long and those within 2 s of the stall stay
start=$(date +%s)
run full BBR_DIAG_PRUNE_MIB=0 STUB_STALL_AT=12 -- -d 40 -n 0 -a 2 -r -H 'echo hooked' \
    -o "$work/full"
check "a run with a stall ends well" [ "$rc" -eq 0 ]
check "the stall is announced" has "$work/full.out" 'stall 1 began'
check "and its end" has "$work/full.out" 'stall 1 ended after 3000 ms'
check "the package is written inside the folder" [ -s "$work/full/full.tar.gz" ]
check "and holds the trace but not itself" sh -c \
    "tar -tzf '$work/full/full.tar.gz' | grep -q 'full/trace.txt' &&
    ! tar -tzf '$work/full/full.tar.gz' | grep -q 'tar.gz'"
check "with the trace" has "$work/full/trace.txt" '^STALL-END'
check "lost packets are reported" has "$work/full.out" 'the capture lost 7 packets'
check "the counters are taken before" [ -s "$work/full/netstat-tcp-before.txt" ]
check "and after" [ -s "$work/full/netstat-tcp-after.txt" ]
check "the interface counters carry no address" lacks "$work/full/netstat-if-after.txt" '02:00:00\|192\.0\.2'
check "the system notes carry no address" lacks "$work/full/system.txt" '02:00:00\|192\.0\.2\|buildhost'
check "but the offload options" has "$work/full/system.txt" 'TSO4'
check "the hook ran" has "$work/full/hook-1.txt" 'hooked'
check "the ring was written at the stall" has "$work/full/ring-1.txt" '^R send'
check "and started again" [ -e "$work/full/ring-2.txt" ]
b=$(sed -n 's/^STALL-BEGIN.* wall=\([0-9]*\)000000000 .*/\1/p' "$work/full/trace.txt")
e=$(sed -n 's/^STALL-END.* wall=\([0-9]*\)000000000 .*/\1/p' "$work/full/trace.txt")
kept=$(ls "$work/full/pcap" | wc -l)
check "the capture during the stall is kept" [ -e "$work/full/pcap/srv-$((b + 1)).pcap" ]
check "and two seconds before it" [ -e "$work/full/pcap/srv-$((b - 2)).pcap" ]
check "and two seconds after it" [ -e "$work/full/pcap/srv-$((e + 1)).pcap" ]
check "but not ten seconds after it" [ ! -e "$work/full/pcap/srv-$((e + 10)).pcap" ]
check "nor the start of the run" [ ! -e "$work/full/pcap/srv-$((start + 1)).pcap" ]
check "about ten files stay of forty" [ "$kept" -ge 7 ]
check "and no more" [ "$kept" -le 14 ]

check "what was removed is listed" has "$work/full/prune.txt" 'removed srv-'

# a list of stalls that misses one must remove nothing
run nolist BBR_DIAG_PRUNE_MIB=0 STUB_STALL_AT=6 STUB_DOUBLE_BEGIN=1 -- \
    -d 30 -n 0 -a 2 -o "$work/nolist"
kept=$(ls "$work/nolist/pcap" | wc -l)
check "an incomplete list of stalls removes nothing" [ "$kept" -ge 25 ]
check "and says so" has "$work/nolist/prune.txt" 'nothing removed: the list has 1 stalls, the trace 2'
check "also in the notes" has "$work/nolist/notes.txt" 'the capture was not pruned'

# a short run is under the size at which pruning starts
run small STUB_STALL_AT=4 -- -d 25 -n 0 -a 2 -o "$work/small"
kept=$(ls "$work/small/pcap" | wc -l)
check "a small capture is kept whole" [ "$kept" -ge 20 ]
check "and nothing is listed as removed" [ ! -e "$work/small/prune.txt" ]

run keepall -- -d 6 -n 0 -k -o "$work/keepall"
kept=$(ls "$work/keepall/pcap" | wc -l)
check "-k keeps the whole capture" [ "$kept" -ge 5 ]

begun=$(date +%s)
run limit -- -d 60 -n 1 -a 2 -o "$work/limit"
took=$(($(date +%s) - begun))
check "-n 1 ends the run after the first stall" has "$work/limit.out" '1 stalls are recorded'
check "well before -d" [ "$took" -lt 30 ]

echo "1..$n"
[ "$fail" -eq 0 ] || echo "# failures; the outputs are in $work"

# the D programs as written, for reading: they are not compiled here
if [ -n "${2:-}" ]; then
    cp "$work/check/bbr-run.d" "$2/bbr-run.d"
    cp "$work/light/bbr-run.d" "$2/bbr-run-light.d"
    cp "$work/full/bbr-ring.d" "$2/bbr-ring.d"
    cp "$work/full.out" "$2/full-run-output.txt"
fi
exit "$fail"
