#!/bin/sh
#
# Record what FreeBSD's BBR TCP stack does while a connection makes no
# progress: the stack's state from DTrace probes, a packet capture of the
# same connections, and the TCP counters before and after, packed in one
# file.
#
# The kernel's tcp_bbr module must carry the "bbr" DTrace provider, which
# the commit "tcp bbr: DTrace probes for a connection that stops sending"
# adds.
#
# usage: bbr-diag [-p port] [-c client] [-i interface] [-o folder]
#                 [-d seconds] [-n stalls] [-s ms] [-g kbit] [-a seconds]
#                 [-M MiB] [-H command] [-k] [-L] [-r] [-C]
#   -p  trace the connections with this local or remote port (default:
#       5201, iperf3)
#   -c  capture only the packets to and from this address
#   -i  capture on this interface (default: the one the client or the
#       default route uses)
#   -o  the folder to write, which must not exist (default:
#       /var/tmp/bbr-diag-<date>)
#   -d  stop after this many seconds (default: when Enter is pressed)
#   -n  stop once this many stalls are recorded (default: 3; 0 for no
#       limit)
#   -s  a stall is this many ms with no progress (default: 1000)
#   -g  progress is more than this many kbit/s acknowledged (default:
#       1000)
#   -a  keep the capture from this many seconds before a stall to this
#       many after it (default: 20)
#   -M  stop when the folder holds this many MiB (default: 4096, or half
#       of the free space if that is less)
#   -H  run this command each time a stall is recorded
#   -k  keep the whole capture, not only the parts around stalls
#   -L  light trace: leave out the probes that fire for every packet
#   -r  also keep a ring of every event, written out when a stall begins
#   -C  check that the trace can run on this kernel, then stop
#
# Run as root. The file to send is the .tar.gz inside the folder.

set -u

port=5201
client=
iface=
stamp=$(date +%Y%m%d-%H%M%S)
out=/var/tmp/bbr-diag-$stamp
duration=0
maxstalls=3
stallms=1000
floorkbit=1000
around=20
maxmib=
hook=
keepall=0
light=0
ring=0
check=0

# the event lines each 100 ms may add while a stall lasts, the 100 ms steps
# of progress that end a stall, and the MiB of events each CPU's ring holds
cap=300
endticks=5
ringmib=16

usage() {
    sed -n '/^# usage:/,/^#   -C/s/^# \{0,1\}//p' "$0" >&2
    exit 2
}

die() {
    echo "bbr-diag: $*" >&2
    exit 1
}

say() {
    echo "bbr-diag: $*"
}

note() {
    echo "$*" >> "$out/notes.txt"
}

while getopts p:c:i:o:d:n:s:g:a:M:H:kLrC opt; do
    case $opt in
        p) port=$OPTARG ;;
        c) client=$OPTARG ;;
        i) iface=$OPTARG ;;
        o) out=$OPTARG ;;
        d) duration=$OPTARG ;;
        n) maxstalls=$OPTARG ;;
        s) stallms=$OPTARG ;;
        g) floorkbit=$OPTARG ;;
        a) around=$OPTARG ;;
        M) maxmib=$OPTARG ;;
        H) hook=$OPTARG ;;
        k) keepall=1 ;;
        L) light=1 ;;
        r) ring=1 ;;
        C) check=1 ;;
        *) usage ;;
    esac
done
[ "$OPTIND" -gt $# ] || usage

for n in "$port" "$duration" "$maxstalls" "$stallms" "$floorkbit" "$around" \
    ${maxmib:+"$maxmib"}; do
    case $n in
        '' | *[!0-9]*) usage ;;
        *) ;;
    esac
done

# sh arithmetic reads a number with a leading zero as octal
decimal() {
    n=${1#"${1%%[1-9]*}"}
    echo "${n:-0}"
}
port=$(decimal "$port")
duration=$(decimal "$duration")
maxstalls=$(decimal "$maxstalls")
stallms=$(decimal "$stallms")
floorkbit=$(decimal "$floorkbit")
around=$(decimal "$around")
[ -z "$maxmib" ] || maxmib=$(decimal "$maxmib")
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "-p takes a TCP port"
[ "$stallms" -ge 200 ] || die "-s takes 200 ms or more"
[ "$floorkbit" -ge 1 ] || die "-g takes 1 kbit/s or more"
# a capture file can hold packets a second older than its name
[ "$around" -ge 2 ] || around=2
# tcpdump reads the capture's file name as a time format
case $out in
    *%*) die "-o takes a folder without % in its name" ;;
    *) ;;
esac
if [ "$light" -eq 1 ] && [ "$ring" -eq 1 ]; then
    die "-r records every packet, which -L leaves out: give one of them"
fi

[ "$(uname -s)" = FreeBSD ] || die "this runs on the FreeBSD server"
[ "$(id -u)" -eq 0 ] || die "run as root"
for tool in dtrace tcpdump netstat sysctl kldstat; do
    command -v "$tool" > /dev/null 2>&1 || die "$tool is needed"
done
if [ "$check" -eq 0 ] && [ "$duration" -eq 0 ] && [ ! -t 0 ]; then
    die "without a terminal, give -d with the seconds to run"
fi

# a stall is so many 100 ms steps, each acknowledging under so many bytes
ticks=$(((stallms + 99) / 100))
floor=$((floorkbit * 125 / 10))
# a capture file is judged once no later stall can still claim it
hold=$((around + 15))

# the capture holds addresses: root alone reads the folder
umask 077
case $out in
    /*) ;;
    *) out=$(pwd)/$out ;;
esac
[ ! -e "$out" ] || die "$out exists; give -o a folder that does not"
mkdir "$out" || die "cannot make $out"
mkdir "$out/pcap" || die "cannot make $out/pcap"
say "writing to $out"

free=$(df -Pk "$out" | awk 'NR == 2 {print int($4 / 1024)}')
[ "${free:-0}" -ge 200 ] || die "only ${free:-0} MiB free in $out"
if [ -z "$maxmib" ]; then
    maxmib=$((free / 2))
    [ "$maxmib" -le 4096 ] || maxmib=4096
fi
# the capture is pruned only once the folder holds a quarter of that, so a
# short run keeps all of it (BBR_DIAG_PRUNE_MIB is for the tests)
prune_at=${BBR_DIAG_PRUNE_MIB:-$((maxmib / 4))}

# ---- the D programs ----

# the connections to trace, by either port
match='(((struct bbrdiag_state *)arg1)->lport == $1 ||
    ((struct bbrdiag_state *)arg1)->fport == $1)'

# The layout the kernel fills for every probe, as bbr.c declares it.
d_struct() {
    cat << 'EOF'
struct bbrdiag_state {
	uint64_t bw_filter;
	uint64_t bw_cur;
	uint64_t bw_lt;
	uint32_t version;
	uint32_t cts;
	uint32_t iss;
	uint32_t snd_una;
	uint32_t snd_max;
	uint32_t snd_nxt;
	uint32_t snd_wnd;
	uint32_t snd_cwnd;
	uint32_t max_sndwnd;
	uint32_t high_rwnd;
	uint32_t flight;
	uint32_t sb_avail;
	uint32_t sacked;
	uint32_t lost_bytes;
	uint32_t lost;
	uint32_t holes_rxt;
	uint32_t delivered;
	uint32_t app_limited_until;
	uint32_t rtt_prop;
	uint32_t srtt;
	uint32_t last_rtt;
	uint32_t rxtcur;
	uint32_t timer_exp;
	uint32_t pacer_started;
	uint32_t last_delay;
	uint32_t agg_delay;
	uint32_t agg_early;
	uint32_t target;
	uint32_t pace_max_segs;
	uint32_t rcvtime;
	uint32_t state_time;
	uint32_t rtt_shrinks;
	uint32_t probertt_int;
	uint32_t enters_probertt;
	uint32_t pkt_epoch;
	uint32_t maps_alloced;
	uint32_t t_flags;
	uint32_t t_flags2;
	uint16_t lport;
	uint16_t fport;
	uint16_t hpts_flags;
	uint16_t pacing_gain;
	uint16_t cwnd_gain;
	uint16_t maxseg;
	uint16_t tlp_cnt;
	uint16_t pace_min_segs;
	uint8_t t_state;
	uint8_t rxtshift;
	uint8_t bbr_state;
	uint8_t bbr_substate;
	uint8_t in_persist;
	uint8_t in_recovery;
	uint8_t in_hpts;
	uint8_t timer_first;
	uint8_t tmr_stopped;
	uint8_t all_stopped;
	uint8_t timer_override;
	uint8_t wanted_output;
	uint8_t cwnd_limited;
	uint8_t has_collapsed;
	uint8_t resend;
	uint8_t tlp_send;
	uint8_t tlp_in_progress;
	uint8_t tlp_rtx_out;
	uint8_t tlp_new_data;
	uint8_t lt_use_bw;
	uint8_t lt_sampling;
	uint8_t use_google;
	uint8_t filled_pipe;
	uint8_t no_pacing;
	uint8_t oerror_cnt;
	uint8_t output_error_seen;
	uint8_t pkt_conservation;
	uint8_t recovery_bw;
	uint8_t timer_src;
	uint8_t past_init_win;
	uint8_t prev_in_rec;
	uint8_t spare;
	uint32_t magic;
	uint32_t size;
};

/* What the pacer reported when the connection was put on its wheel. */
struct bbrdiag_hpts {
	uint32_t p_hpts_active;
	uint32_t p_nxt_slot;
	uint32_t p_cur_slot;
	uint32_t p_prev_slot;
	uint32_t p_runningslot;
	uint32_t slot_req;
	uint32_t inp_hptsslot;
	uint32_t slot_remaining;
	uint32_t have_slept;
	uint32_t hpts_sleep_time;
	uint32_t yet_to_sleep;
	uint32_t need_new_to;
	uint32_t wheel_slot;
	uint32_t maxslots;
	uint32_t wheel_cts;
	int32_t co_ret;
	uint32_t p_curtick;
	uint32_t p_lasttick;
	uint8_t p_on_min_sleep;
};

EOF
}

# The rest of an event or state line: every member of the snapshot.
d_state() {
    cat << 'EOF'
	printf(" cts=%u una=%u max=%u nxt=%u iss=%u wnd=%u mxw=%u hirw=%u",
	    this->s->cts, this->s->snd_una, this->s->snd_max, this->s->snd_nxt,
	    this->s->iss, this->s->snd_wnd, this->s->max_sndwnd,
	    this->s->high_rwnd);
	printf(" cwnd=%u tgt=%u flight=%u sb=%u sacked=%u lostb=%u lost=%u",
	    this->s->snd_cwnd, this->s->target, this->s->flight,
	    this->s->sb_avail, this->s->sacked, this->s->lost_bytes,
	    this->s->lost);
	printf(" holes=%u deliv=%u appl=%u maps=%u bw=%d bwcur=%d bwlt=%d",
	    this->s->holes_rxt, this->s->delivered, this->s->app_limited_until,
	    this->s->maps_alloced, this->s->bw_filter, this->s->bw_cur,
	    this->s->bw_lt);
	printf(" rttp=%u srtt=%u lrtt=%u rxtcur=%u rxtshift=%d hf=%x texp=%u",
	    this->s->rtt_prop, this->s->srtt, this->s->last_rtt,
	    this->s->rxtcur, this->s->rxtshift, this->s->hpts_flags,
	    this->s->timer_exp);
	printf(" pstart=%u delay=%u aggd=%u agge=%u pmax=%u pmin=%u mss=%u",
	    this->s->pacer_started, this->s->last_delay, this->s->agg_delay,
	    this->s->agg_early, this->s->pace_max_segs, this->s->pace_min_segs,
	    this->s->maxseg);
	printf(" rcvt=%u stt=%u rtts=%u prtti=%u prtte=%u pe=%u",
	    this->s->rcvtime, this->s->state_time, this->s->rtt_shrinks,
	    this->s->probertt_int, this->s->enters_probertt,
	    this->s->pkt_epoch);
	printf(" tstate=%d st=%d sub=%d pgain=%d cgain=%d per=%d rec=%d hpts=%d",
	    this->s->t_state, this->s->bbr_state, this->s->bbr_substate,
	    this->s->pacing_gain, this->s->cwnd_gain, this->s->in_persist,
	    this->s->in_recovery, this->s->in_hpts);
	printf(" tfirst=%d tstop=%x allstop=%d tovr=%d want=%d cwl=%d coll=%d",
	    this->s->timer_first, this->s->tmr_stopped, this->s->all_stopped,
	    this->s->timer_override, this->s->wanted_output,
	    this->s->cwnd_limited, this->s->has_collapsed);
	printf(" rs=%d tlps=%d tlpip=%d tlpro=%d tlpnd=%d tlpc=%d ltu=%d lts=%d",
	    this->s->resend, this->s->tlp_send, this->s->tlp_in_progress,
	    this->s->tlp_rtx_out, this->s->tlp_new_data, this->s->tlp_cnt,
	    this->s->lt_use_bw, this->s->lt_sampling);
	printf(" goog=%d fill=%d nopace=%d oerr=%d oerrs=%d pcons=%d recbw=%d",
	    this->s->use_google, this->s->filled_pipe, this->s->no_pacing,
	    this->s->oerror_cnt, this->s->output_error_seen,
	    this->s->pkt_conservation, this->s->recovery_bw);
	printf(" tsrc=%d piw=%d pir=%d fl=%x fl2=%x lp=%d fp=%d\n",
	    this->s->timer_src, this->s->past_init_win, this->s->prev_in_rec,
	    this->s->t_flags, this->s->t_flags2, this->s->lport,
	    this->s->fport);
EOF
}

# One event line: the probe, its four values, then the snapshot.
d_print() {
    cat << 'EOF'
	this->s = (struct bbrdiag_state *)arg1;
	printf("EV %s ts=%d tp=%x a2=%d a3=%d a4=%d a5=%x", probename,
	    timestamp, arg0, arg2, arg3, arg4, arg5);
EOF
    d_state
}

# d_event probes always budget: clauses that print these probes when
# "always" holds, up to the budget of each 100 ms, and otherwise only while
# a stall lasts. always 1 prints every one, always 0 only during a stall.
d_event() {
    ev_probes=$1
    ev_always=$2
    ev_budget=$3
    if [ "$ev_always" != 0 ]; then
        cat << EOF
$ev_probes
/($ev_always) && $ev_budget > 0 && $match/
{
	$ev_budget--;
EOF
        d_print
        printf '}\n\n'
    fi
    if [ "$ev_always" != 1 ]; then
        cat << EOF
$ev_probes
/detail && b_detail > 0 && !($ev_always) && $match/
{
	b_detail--;
EOF
        d_print
        printf '}\n\n'
    fi
}

# The trace: a state line each 100 ms, the rare events, a count of the
# reasons each second, and every event while a stall lasts.
d_trace() {
    cat << 'EOF'
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option switchrate=20hz
#pragma D option aggrate=20hz
#pragma D option strsize=32

EOF
    d_struct
    cat << 'EOF'
int detail;		/* a stall lasts: print every event */
int want;		/* the next segment prints a state line */
int live;		/* the data connection is established */
int stalled;
int quiet;		/* 100 ms steps in a row without progress */
int moving;		/* 100 ms steps in a row with progress */
int nstall;
int checked;		/* 0 not yet, 1 layout differs, 2 layout agrees */
int g_state;		/* BBR state last printed */
int b_rare;		/* lines left in this 100 ms: rare events */
int b_rxt;		/* retransmissions */
int b_detail;		/* events of a stall */
int b_base;		/* the base kernel's probes */
uint64_t s_tp;		/* the connection of the last state line */
uint64_t p_tp;		/* and of the one a step earlier */
uint64_t big_tp;	/* the data connection: seen with 32 KB in flight */
uint64_t s_seq;		/* state lines so far */
uint64_t p_seq;
uint64_t t_stall;
uint32_t s_una;
uint32_t p_una;
uint32_t s_flight;
uint32_t s_sb;

dtrace:::BEGIN
{
	big_tp = 0;
	b_base = 50;
	s_flight = 0;
	s_sb = 0;
	detail = 0;
	want = 1;
	live = 0;
	stalled = 0;
	quiet = 0;
	moving = 0;
	nstall = 0;
	checked = 0;
	g_state = -1;
	b_rare = 100;
	b_rxt = 50;
	b_detail = $4;
	s_tp = 0;
	p_tp = 0;
	s_seq = 0;
	p_seq = 0;
	s_una = 0;
	p_una = 0;
	printf("BEGIN ts=%d wall=%d port=%d stall_steps=%d floor_bytes=%d",
	    timestamp, walltimestamp, $1, $2, $3);
	printf(" cap=%d end_steps=%d\n", $4, $5);
}

EOF
    # The layout is judged on the first event of any connection: the port
    # test itself reads the snapshot.
    cat << EOF
bbr:::input-done, bbr:::conn-init
/!checked/
{
	this->s = (struct bbrdiag_state *)arg1;
	checked = (this->s->magic == 0x42425253 &&
	    this->s->size == sizeof (struct bbrdiag_state)) ? 2 : 1;
	printf("LAYOUT ts=%d magic=%x size=%d expect=%d version=%d\n",
	    timestamp, this->s->magic, this->s->size,
	    sizeof (struct bbrdiag_state), this->s->version);
}

bbr:::input-done, bbr:::conn-init
/checked == 1/
{
	checked = 3;
	printf("LAYOUT-MISMATCH the kernel's snapshot is not the one ");
	printf("this script declares\n");
	exit(3);
}

bbr:::input-done
/want && $match && (big_tp == 0 || arg0 == big_tp ||
    ((struct bbrdiag_state *)arg1)->flight > 32768)/
{
	want = 0;
	this->s = (struct bbrdiag_state *)arg1;
	s_seq++;
	s_tp = arg0;
	s_una = this->s->snd_una;
	s_flight = this->s->flight;
	s_sb = this->s->sb_avail;
	big_tp = (this->s->flight > 32768) ? arg0 : big_tp;
	live = (this->s->t_state == 4 && arg0 == big_tp) ? 1 : 0;
	printf("STATE ts=%d tp=%x", timestamp, arg0);
EOF
    d_state
    printf '}\n\n'

    d_event "bbr:::conn-fini, bbr:::input-drop, bbr:::output-error,
bbr:::timeout, bbr:::persist, bbr:::recovery-enter, bbr:::recovery-exit,
bbr:::rtt-shrinks" 1 b_rare

    # BBR attaches before the connection has its ports, so the port test
    # cannot pick the traced one: every new connection prints
    cat << 'EOF'
bbr:::conn-init
/b_rare > 0/
{
	b_rare--;
EOF
    d_print
    printf '}\n\n'

    # A change of the BBR state always prints; a change of the gain cycle
    # within one state only while a stall lasts. The second clause moves
    # g_state, so it comes last.
    cat << EOF
bbr:::conn-fini
/arg0 == big_tp/
{
	live = 0;
	big_tp = 0;
}

bbr:::state-change
/detail && b_detail > 0 &&
    ((struct bbrdiag_state *)arg1)->bbr_state == g_state && $match/
{
	b_detail--;
EOF
    d_print
    cat << EOF
}

bbr:::state-change
/((struct bbrdiag_state *)arg1)->bbr_state != g_state && b_rare > 0 &&
    $match/
{
	b_rare--;
	g_state = ((struct bbrdiag_state *)arg1)->bbr_state;
EOF
    d_print
    printf '}\n\n'

    d_event "bbr:::rwnd-collapse" \
        "arg2 == 0 || (arg2 == 1 &&
    ((struct bbrdiag_state *)arg1)->has_collapsed == 0)" b_rare

    if [ "$light" -eq 0 ]; then
        d_event "bbr:::cwnd" "(int)arg2 >= 12" b_rare
        d_event "bbr:::timer-check" \
            "(int)arg2 != -1 && (int)arg2 != -2" b_rare
        d_event "bbr:::timer-start" \
            "(arg3 == 0 && arg4 == 0) || arg4 >= 1000000" b_rare
        d_event "bbr:::nosend" "arg2 == 5 || arg2 == 6" b_rare
        d_event "bbr:::lt-bw" "arg2 != 6" b_rare
        d_event "bbr:::input, bbr:::output, bbr:::timer-busy,
bbr:::timer-cancel, bbr:::fastack-bail" 0 b_rare

        # A send that failed always prints, and so does a retransmission or
        # a tail loss probe, from a budget of its own. The clause that
        # spends that budget comes last, so the one before it sees what is
        # left.
        cat << EOF
bbr:::send
/arg4 != 0 && b_rare > 0 && $match/
{
	b_rare--;
EOF
        d_print
        cat << EOF
}

bbr:::send
/detail && b_detail > 0 && arg4 == 0 &&
    ((arg5 & 0x30000) == 0 || b_rxt <= 0) && $match/
{
	b_detail--;
EOF
        d_print
        cat << EOF
}

bbr:::send
/arg4 == 0 && (arg5 & 0x30000) != 0 && b_rxt > 0 && $match/
{
	b_rxt--;
EOF
        d_print
        cat << EOF
}

bbr:::timer-start
/detail && b_detail > 0 && arg5 != 0 && $match/
{
	b_detail--;
	this->h = (struct bbrdiag_hpts *)arg5;
	printf("HPTS ts=%d tp=%x active=%d nxt=%d cur=%d prev=%d running=%d",
	    timestamp, arg0, this->h->p_hpts_active, this->h->p_nxt_slot,
	    this->h->p_cur_slot, this->h->p_prev_slot,
	    this->h->p_runningslot);
	printf(" req=%d slot=%d remain=%d slept=%d sleep=%d yet=%d newto=%d",
	    this->h->slot_req, this->h->inp_hptsslot,
	    this->h->slot_remaining, this->h->have_slept,
	    this->h->hpts_sleep_time, this->h->yet_to_sleep,
	    this->h->need_new_to);
	printf(" wheel=%d max=%d wcts=%u co=%d minsleep=%d\n",
	    this->h->wheel_slot, this->h->maxslots, this->h->wheel_cts,
	    this->h->co_ret, this->h->p_on_min_sleep);
}

bbr:::nosend
/$match/
{
	@ns[arg2] = count();
}

bbr:::fastack-bail
/$match/
{
	@fa[arg2] = count();
}

profile:::tick-1sec, dtrace:::END
{
	printf("COUNTS ts=%d wall=%d\n", timestamp, walltimestamp);
	printa("NOSEND reason=%d n=%@d\n", @ns);
	printa("FASTACK reason=%d n=%@d\n", @fa);
	trunc(@ns);
	trunc(@fa);
}

EOF
    fi
    d_event "bbr:::input-done" 0 b_rare

    cat << 'EOF'
/*
 * Each 100 ms: 1 when the data connection is established and acknowledged
 * less than the floor, whether or not it had data to send; 2 when it
 * acknowledged more; 0 when there is nothing to judge.
 */
profile:::tick-100ms
{
	this->st = !live ? 0 : (s_seq == p_seq) ? 1 : (s_tp != p_tp) ? 0 :
	    ((uint32_t)(s_una - p_una) < $3) ? 1 : 2;
	quiet = (this->st == 1) ? quiet + 1 :
	    (this->st == 2 || !live) ? 0 : quiet;
	moving = (this->st == 2) ? moving + 1 : (this->st == 1) ? 0 : moving;
	printf("TICK ts=%d wall=%d step=%d quiet=%d moving=%d live=%d",
	    timestamp, walltimestamp, this->st, quiet, moving, live);
	printf(" stalled=%d left_rare=%d left_rxt=%d left_detail=%d",
	    stalled, b_rare, b_rxt, b_detail);
	printf(" left_base=%d\n", b_base);
	p_seq = s_seq;
	p_tp = s_tp;
	p_una = s_una;
	want = 1;
	b_rare = 100;
	b_rxt = 50;
	b_detail = $4;
	b_base = 50;
}

profile:::tick-100ms
/!stalled && quiet >= $2/
{
	stalled = 1;
	detail = 1;
	moving = 0;
	nstall++;
	t_stall = timestamp;
	printf("STALL-BEGIN id=%d ts=%d wall=%d tp=%x una=%u quiet=%d",
	    nstall, timestamp, walltimestamp, s_tp, s_una, quiet);
	printf(" flight=%u sb=%u\n", s_flight, s_sb);
}

profile:::tick-100ms
/stalled && (moving >= $5 || !live)/
{
	printf("STALL-END id=%d ts=%d wall=%d ms=%d live=%d\n", nstall,
	    timestamp, walltimestamp, (timestamp - t_stall) / 1000000, live);
	stalled = 0;
	detail = 0;
	quiet = 0;
	moving = 0;
}

dtrace:::END
{
	printf("END ts=%d wall=%d stalls=%d\n", timestamp, walltimestamp,
	    nstall);
}
EOF
}

# What the base kernel already traces, added where this kernel has it: the
# TCP state of every connection, drops, and the segments the stack throws
# away outside bbr.c.
d_extras() {
    if has_probe 'fbt::tcp_state_change:entry'; then
        cat << 'EOF'

fbt::tcp_state_change:entry
/b_base > 0/
{
	b_base--;
	printf("XEV tcp-state ts=%d tp=%x new=%d\n", timestamp, arg0, arg1);
}

fbt::tcp_state_change:entry
/arg0 == big_tp && arg1 != 4/
{
	live = 0;
	big_tp = 0;
}
EOF
    fi
    if has_probe 'fbt::tcp_drop:entry'; then
        cat << 'EOF'

fbt::tcp_drop:entry
/b_base > 0/
{
	b_base--;
	printf("XEV tcp-drop ts=%d tp=%x errno=%d\n", timestamp, arg0, arg1);
}
EOF
    fi
    for f in ctf_do_drop ctf_do_dropafterack ctf_do_dropwithreset \
        ctf_do_dropwithreset_conn; do
        has_probe "fbt:tcp_bbr:$f:entry" || continue
        cat << EOF

fbt:tcp_bbr:$f:entry
/b_base > 0/
{
	b_base--;
	printf("XEV %s ts=%d tp=%x\n", probefunc, timestamp, arg1);
}
EOF
    done
    for f in ctf_ts_check ctf_challenge_ack; do
        has_probe "fbt:tcp_bbr:$f:entry" || continue
        cat << EOF

fbt:tcp_bbr:$f:entry
/b_base > 0/
{
	b_base--;
	printf("XEV %s ts=%d tp=%x\n", probefunc, timestamp, arg2);
}
EOF
    done
}

# -r: every event of the traced connections in a ring per CPU, which
# dtrace writes out when it is stopped.
d_ring() {
    cat << EOF
#pragma D option quiet
#pragma D option bufpolicy=ring
#pragma D option bufsize=${ringmib}m
#pragma D option strsize=32

EOF
    d_struct
    cat << EOF
bbr:::
/((struct bbrdiag_state *)arg1)->magic == 0x42425253 &&
    ((struct bbrdiag_state *)arg1)->size == sizeof (struct bbrdiag_state) &&
    $match/
{
	this->s = (struct bbrdiag_state *)arg1;
	printf("R %s ts=%d tp=%x a2=%d a3=%d a4=%d a5=%x", probename,
	    timestamp, arg0, arg2, arg3, arg4, arg5);
	printf(" cts=%u una=%u max=%u wnd=%u cwnd=%u flight=%u sb=%u",
	    this->s->cts, this->s->snd_una, this->s->snd_max,
	    this->s->snd_wnd, this->s->snd_cwnd, this->s->flight,
	    this->s->sb_avail);
	printf(" sacked=%u lostb=%u hf=%x texp=%u delay=%u st=%d sub=%d",
	    this->s->sacked, this->s->lost_bytes, this->s->hpts_flags,
	    this->s->timer_exp, this->s->last_delay, this->s->bbr_state,
	    this->s->bbr_substate);
	printf(" pgain=%d rxtshift=%d per=%d rec=%d hpts=%d rs=%d\n",
	    this->s->pacing_gain, this->s->rxtshift, this->s->in_persist,
	    this->s->in_recovery, this->s->in_hpts, this->s->resend);
}
EOF
}

# ---- can the trace run here? ----

# dtrace -l reports a description that matches no probe on stderr, below
# its header line, and exits 0
has_probe() {
    dtrace -x nolibs -l -n "$1" 2> /dev/null \
        | awk 'NR > 1 {n++} END {exit n == 0}'
}

# the kernel this is, without the name of the host that built it
kernel_id() {
    uname -v | sed 's/ [^ ]*@[^ ]*$//'
}

probes="conn-init conn-fini input input-done input-drop fastack-bail output
nosend send output-error timer-start timer-busy timer-cancel timer-check
timeout persist state-change rtt-shrinks cwnd rwnd-collapse lt-bw
recovery-enter recovery-exit"

{
    echo "== kernel"
    kernel_id
    echo "running kernel: $(freebsd-version -r 2> /dev/null)"
    echo "userland: $(freebsd-version -u 2> /dev/null)"
} > "$out/check.txt" 2>&1

if ! kldstat -q -m dtraceall; then
    kldload dtraceall >> "$out/check.txt" 2>&1 \
        || die "cannot load the DTrace modules (kldload dtraceall);" \
            "the message is in $out/check.txt"
fi
echo "== dtrace" >> "$out/check.txt"
if ! dtrace -x nolibs -q -n 'dtrace:::BEGIN { exit(0); }' \
    >> "$out/check.txt" 2>&1; then
    tail -3 "$out/check.txt" >&2
    die "DTrace does not run on this kernel. With a 15 kernel under a 16" \
        "userland the two halves may not match: boot the kernel that" \
        "matches /usr/sbin/dtrace, or build dtrace from the kernel's" \
        "source. The full message is in $out/check.txt"
fi
say "DTrace runs on this kernel"

kldstat -q -m tcp_bbr \
    || die "the tcp_bbr module is not loaded: run 'kldload tcp_bbr'"
echo "== bbr probes" >> "$out/check.txt"
dtrace -x nolibs -l -P bbr 2>> "$out/check.txt" \
    | awk 'NR > 1 {print $NF}' | sort -u > "$out/.probes"
cat "$out/.probes" >> "$out/check.txt"
missing=
found=0
for p in $probes; do
    if grep -q -x -e "$p" "$out/.probes"; then
        found=$((found + 1))
    else
        missing="$missing $p"
    fi
done
rm -f "$out/.probes"
if [ "$found" -eq 0 ]; then
    die "the loaded tcp_bbr module has no bbr probes, so this kernel was" \
        "not built from the source this script came with. Running:" \
        "$(kernel_id)"
fi
[ -z "$missing" ] || die "the loaded tcp_bbr module lacks these probes:" \
    "$missing. Build the kernel and this script from the same commit"
say "the tcp_bbr module has all $found bbr probes"

# the trace must compile before a run is worth starting; what the base
# kernel adds is left out if only that part fails
d_trace > "$out/bbr-trace.d"
d_extras > "$out/bbr-extras.d"
cat "$out/bbr-trace.d" "$out/bbr-extras.d" > "$out/bbr-run.d"
compile() {
    echo "== compile $1" >> "$out/check.txt"
    dtrace -x nolibs -e -s "$1" "$port" "$ticks" "$floor" "$cap" \
        "$endticks" > /dev/null 2> "$out/.compile"
    status=$?
    cat "$out/.compile" >> "$out/check.txt"
    return "$status"
}
if ! compile "$out/bbr-run.d"; then
    if compile "$out/bbr-trace.d"; then
        cp "$out/bbr-trace.d" "$out/bbr-run.d"
        note "the base kernel's probes do not compile here and were left" \
            "out: no tcp-state, tcp-drop or ctf lines"
        say "the base kernel's own probes do not compile here: left out"
    else
        head -5 "$out/.compile" >&2
        rm -f "$out/.compile"
        die "the trace script does not compile on this system; the" \
            "message above is also in $out/check.txt. The script is" \
            "$out/bbr-trace.d"
    fi
fi
rm -f "$out/.compile" "$out/bbr-extras.d"
say "the trace script compiles"
if [ "$ring" -eq 1 ]; then
    d_ring > "$out/bbr-ring.d"
    echo "== compile bbr-ring.d" >> "$out/check.txt"
    dtrace -x nolibs -e -s "$out/bbr-ring.d" "$port" > /dev/null \
        2>> "$out/check.txt" \
        || die "the ring script does not compile; the message is in" \
            "$out/check.txt. Run without -r"
fi

if [ "$check" -eq 1 ]; then
    say "every check passed. Next: run again without -C, then start iperf3"
    exit 0
fi

# ---- the system and its counters ----

if [ -z "$iface" ]; then
    iface=$(route -n get "${client:-default}" 2> /dev/null \
        | awk '/interface:/ {print $2}')
fi
[ -n "$iface" ] || die "no interface found; give -i"

{
    uname -srm
    echo "running kernel: $(freebsd-version -r 2> /dev/null)"
    echo "userland: $(freebsd-version -u 2> /dev/null)"
    kernel_id
    sysctl kern.osreldate kern.ident kern.hz kern.timecounter.hardware \
        kern.vm_guest hw.model hw.ncpu hw.physmem kern.ipc.maxsockbuf \
        kern.ipc.nmbclusters net.bpf.maxbufsize 2> /dev/null
    sysctl net.inet.tcp.functions_default net.inet.tcp.functions_available \
        net.inet.tcp.cc.algorithm net.inet.tcp.delayed_ack \
        net.inet.tcp.delacktime net.inet.tcp.tso net.inet.tcp.sack.enable \
        net.inet.tcp.rfc1323 net.inet.tcp.sendbuf_auto \
        net.inet.tcp.sendbuf_max net.inet.tcp.sendbuf_inc \
        net.inet.tcp.recvbuf_auto net.inet.tcp.recvbuf_max \
        net.inet.tcp.sendspace net.inet.tcp.recvspace net.inet.tcp.mssdflt \
        net.inet.tcp.minmss net.inet.tcp.insecure_ack \
        net.inet.tcp.tolerate_missing_ts net.inet.tcp.always_keepalive \
        net.inet.tcp.keepidle net.inet.tcp.msl net.inet.tcp.initcwnd_segments \
        net.inet.tcp.pmtud_blackhole_detection 2> /dev/null
    echo "interface $iface"
    ifconfig "$iface" 2> /dev/null \
        | grep -E 'flags=|options=|media:|status:|mtu'
    kldstat
} > "$out/system.txt" 2>&1

snapshot() {
    tag=$1
    netstat -s -p tcp > "$out/netstat-tcp-$tag.txt" 2>&1
    sysctl net.inet.tcp.bbr > "$out/sysctl-bbr-$tag.txt" 2>&1
    sysctl net.inet.tcp.hpts net.inet.tcp.bb \
        > "$out/sysctl-pacer-$tag.txt" 2>&1
    netstat -m > "$out/netstat-m-$tag.txt" 2>&1
    vmstat -z > "$out/vmstat-z-$tag.txt" 2>&1
    # the interface's counters, without its address
    netstat -I "$iface" -b -d -n 2> /dev/null \
        | awk 'NR == 1 {print; next} $3 ~ /^<Link/ {$4 = "-"; print}' \
        > "$out/netstat-if-$tag.txt"
}

snapshot before
date +%s > "$out/times.txt"

# ---- the capture and the trace ----

# As a background job of this shell dtrace ignores SIGINT; tcpdump takes it
# and stops by itself. Both stop on SIGTERM, also when this shell is ended
# by a signal or a closed pipe.
tcpdump_pid=
dtrace_pid=
ring_pid=
ring_n=0
reader=
stop_all() {
    for p in $ring_pid $dtrace_pid $tcpdump_pid $reader; do
        kill -TERM "$p" 2> /dev/null
    done
}
abort_run() {
    stop_all
    exit "${1:-130}"
}
trap stop_all EXIT
trap abort_run INT TERM HUP PIPE

# ten seconds a file, named by the second it starts: -Z root because a
# tcpdump that gives up root could not write in this folder
filter="tcp port $port${client:+ and host $client}"
tcpdump -i "$iface" -s 128 -B 16384 -Z root -G 10 \
    -w "$out/pcap/srv-%s.pcap" "$filter" 2> "$out/tcpdump.txt" &
tcpdump_pid=$!

ring_start() {
    ring_n=$((ring_n + 1))
    dtrace -x nolibs -s "$out/bbr-ring.d" -o "$out/ring-$ring_n.txt" \
        "$port" 2> "$out/ring-$ring_n.err" &
    ring_pid=$!
}
# stopping the ring is what makes dtrace write it out
ring_write() {
    [ -n "$ring_pid" ] || return 0
    kill -TERM "$ring_pid" 2> /dev/null
    wait "$ring_pid" 2> /dev/null
    ring_pid=
}

dtrace -x nolibs -s "$out/bbr-run.d" -o "$out/trace.txt" "$port" "$ticks" \
    "$floor" "$cap" "$endticks" 2> "$out/trace.err" &
dtrace_pid=$!
[ "$ring" -eq 0 ] || ring_start

# the trace ends itself when the kernel fills a snapshot other than the one
# this script declares
layout_differs() {
    grep -q '^LAYOUT-MISMATCH' "$out/trace.txt" 2> /dev/null || return 1
    echo "bbr-diag: the kernel's snapshot and this script's differ: use" \
        "the script from the commit the kernel was built from" >&2
}

# the trace runs once it has written its first line; compiling it and
# placing its probes can take some seconds
waited=0
until grep -q '^BEGIN' "$out/trace.txt" 2> /dev/null; do
    kill -0 "$dtrace_pid" 2> /dev/null || break
    [ "$waited" -lt 120 ] || break
    sleep 1
    waited=$((waited + 1))
done
if ! kill -0 "$tcpdump_pid" 2> /dev/null; then
    echo "bbr-diag: tcpdump exited: $(cat "$out/tcpdump.txt")" >&2
    abort_run 1
fi
if ! kill -0 "$dtrace_pid" 2> /dev/null; then
    layout_differs \
        || echo "bbr-diag: the trace exited: $(cat "$out/trace.err")" >&2
    abort_run 1
fi
if ! grep -q '^BEGIN' "$out/trace.txt" 2> /dev/null; then
    echo "bbr-diag: the trace did not start within $waited s:" \
        "$(tail -3 "$out/trace.err")" >&2
    abort_run 1
fi

# Remove the capture files no stall needs. A file runs from the second in
# its name to the start of the next one; the newest is still being written.
# $1 is 1 once the capture has stopped, when the last two files stay as a
# sample of the traffic.
prune_noted=0
prune_skip() {
    echo "$(date +%s) nothing removed: $*" >> "$out/prune.txt"
    [ "$prune_noted" -eq 0 ] || return 0
    prune_noted=1
    note "the capture was not pruned: $*"
}
prune() {
    [ "$keepall" -eq 0 ] || return 0
    # Every stall of the trace must be in the list, or nothing is removed:
    # with a stall missing, the files around it would go.
    want=$(count STALL-BEGIN)
    if ! awk '
        function wall(   i) {
            for (i = 2; i <= NF; i++)
                if ($i ~ /^wall=/)
                    return int(substr($i, 6) / 1000000000)
            return 0
        }
        $1 == "STALL-BEGIN" {b = wall(); open = 1}
        $1 == "STALL-END" && open {print b, wall(); open = 0}
        END {if (open) print b, 0}
    ' "$out/trace.txt" > "$out/.stalls" 2>> "$out/prune.txt"; then
        prune_skip "the list of stalls could not be made"
        return 0
    fi
    got=$(awk 'END {print NR}' "$out/.stalls")
    if [ "${got:-0}" -ne "$want" ]; then
        prune_skip "the list has ${got:-0} stalls, the trace $want"
        return 0
    fi
    {
        sed 's/^/stall /' "$out/.stalls"
        ls "$out/pcap" | sort | sed 's/^/file /'
    } | awk -v now="$(date +%s)" -v around="$around" -v hold="$hold" \
        -v final="$1" '
        $1 == "stall" {
            nw++
            wb[nw] = $2
            we[nw] = ($3 == 0 ? now : $3)
            next
        }
        {
            n++
            name[n] = $2
            s = $2
            sub(/^srv-/, "", s)
            sub(/\.pcap$/, "", s)
            start[n] = s + 0
        }
        END {
            for (i = 1; i <= n; i++) {
                end = (i < n ? start[i + 1] : now)
                if (!final && (i == n || end > now - hold))
                    continue
                keep = (final && i >= n - 1)
                for (j = 1; j <= nw; j++)
                    if (start[i] <= we[j] + around && end >= wb[j] - around)
                        keep = 1
                if (!keep)
                    print name[i]
            }
        }
    ' | while read -r f; do
        rm -f "${out:?}/pcap/${f:?}"
        echo "$(date +%s) removed $f, stalls known: $want" >> "$out/prune.txt"
    done
    rm -f "$out/.stalls"
}

count() {
    n=$(grep -c "^$1" "$out/trace.txt" 2> /dev/null)
    echo "${n:-0}"
}

# Ctrl-C ends the wait, and the run goes on to its counters and its package
stop=0
trap 'stop=1' INT
say "capturing on $iface and tracing TCP port $port. A stall is $stallms ms" \
    "under $floorkbit kbit/s"
if [ "$duration" -gt 0 ]; then
    say "start iperf3 now. The run ends after $duration s, or with Ctrl-C"
    end=$(($(date +%s) + duration))
else
    say "start iperf3 now. Enter or Ctrl-C ends the run"
    end=0
    # the read runs in the background, from the terminal on descriptor 3,
    # so the loop below sees Enter and everything else it waits for
    exec 3<&0
    (
        read -r _ <&3
        : > "$out/.enter"
    ) &
    reader=$!
fi
[ "$maxstalls" -eq 0 ] || say "it also ends once $maxstalls stalls are recorded"

status=0
begun=0
ended=0
ended_at=0
loops=0
while [ "$stop" -eq 0 ]; do
    sleep 1
    # Ctrl-C has ended tcpdump too: that is no failure
    [ "$stop" -eq 0 ] || break
    loops=$((loops + 1))
    now=$(date +%s)
    if ! kill -0 "$dtrace_pid" 2> /dev/null; then
        layout_differs || echo "bbr-diag: the trace stopped:" \
            "$(tail -3 "$out/trace.err")" >&2
        status=1
        break
    fi
    if ! kill -0 "$tcpdump_pid" 2> /dev/null; then
        echo "bbr-diag: tcpdump stopped: $(tail -1 "$out/tcpdump.txt")" >&2
        status=1
        break
    fi
    [ ! -e "$out/.enter" ] || break
    [ "$end" -eq 0 ] || [ "$now" -lt "$end" ] || break

    n=$(count STALL-BEGIN)
    if [ "$n" -gt "$begun" ]; then
        begun=$n
        say "$(date +%T) stall $begun began"
        if [ "$ring" -eq 1 ]; then
            ring_write
            ring_start
        fi
    fi
    n=$(count STALL-END)
    if [ "$n" -gt "$ended" ]; then
        ended=$n
        ended_at=$now
        ms=$(sed -n 's/^STALL-END.* ms=\([0-9]*\).*/\1/p' "$out/trace.txt" \
            | tail -1)
        say "$(date +%T) stall $ended ended after ${ms:-?} ms"
        if [ -n "$hook" ]; then
            sh -c "$hook" > "$out/hook-$ended.txt" 2>&1 &
        fi
    fi
    if [ "$maxstalls" -gt 0 ] && [ "$ended" -ge "$maxstalls" ] \
        && [ $((now - ended_at)) -ge "$around" ]; then
        say "$ended stalls are recorded"
        break
    fi

    if [ $((loops % 5)) -eq 0 ]; then
        used=$(du -sk "$out" | awk '{print int($1 / 1024)}')
        if [ "${used:-0}" -ge "$prune_at" ]; then
            prune 0
            used=$(du -sk "$out" | awk '{print int($1 / 1024)}')
        fi
        if [ "${used:-0}" -ge "$maxmib" ]; then
            say "the folder reached its limit of $maxmib MiB"
            note "the run stopped at its limit of $maxmib MiB"
            break
        fi
    fi
done
trap abort_run INT
if [ -n "$reader" ]; then
    kill "$reader" 2> /dev/null
    exec 3<&-
    reader=
fi
rm -f "$out/.enter"

say "stopping the capture and the trace"
ring_write
kill -TERM "$dtrace_pid" 2> /dev/null
kill -TERM "$tcpdump_pid" 2> /dev/null
# a trace that failed has exited with a status; one stopped here exits 0
if ! wait "$dtrace_pid"; then
    echo "bbr-diag: the trace failed: $(tail -3 "$out/trace.err")" >&2
    status=1
fi
if ! wait "$tcpdump_pid"; then
    echo "bbr-diag: tcpdump failed: $(tail -1 "$out/tcpdump.txt")" >&2
    status=1
fi
dtrace_pid=
tcpdump_pid=
date +%s >> "$out/times.txt"
snapshot after
used=$(du -sk "$out" | awk '{print int($1 / 1024)}')
[ "${used:-0}" -lt "$prune_at" ] || prune 1
trap - INT TERM HUP PIPE

if layout_differs; then
    status=1
elif ! grep -q '^STATE' "$out/trace.txt" 2> /dev/null; then
    say "no connection on port $port was seen: was iperf3 running, and" \
        "is the stack BBR (sysctl net.inet.tcp.functions_default)?"
    note "no traced connection was seen"
fi
drops=$(grep -c -i 'drop' "$out/trace.err" 2> /dev/null)
if [ "${drops:-0}" -gt 0 ]; then
    say "dtrace lost trace records: see $out/trace.err"
    note "dtrace reported drops: see trace.err"
fi
[ -s "$out/trace.err" ] || rm -f "$out/trace.err"
# the kernel lowers tcpdump's buffer to net.bpf.maxbufsize without a word
lost=$(sed -n 's/^\([0-9][0-9]*\) packets dropped by kernel.*/\1/p' \
    "$out/tcpdump.txt" | tail -1)
if [ "${lost:-0}" -gt 0 ]; then
    say "the capture lost $lost packets: raise net.bpf.maxbufsize (now" \
        "$(sysctl -n net.bpf.maxbufsize 2> /dev/null)) before the next run"
    note "the capture lost $lost packets"
fi

stalls=$(count STALL-BEGIN)
note "stalls recorded: $stalls"
say "stalls recorded: $stalls"
# the package goes inside the folder, which only root can write
name=$(basename "$out")
pkg=$out/$name.tar.gz
if ! tar -czf "$pkg" -C "$(dirname "$out")" --exclude "$name.tar.gz" \
    "$name"; then
    rm -f "${out:?}/${name:?}.tar.gz"
    die "packing $out failed; the files are still there"
fi
size=$(du -sk "$pkg" | awk '{print int($1 / 1024)}')
if [ "$status" -eq 0 ]; then
    say "done. Send $pkg ($size MiB); its capture holds both hosts'" \
        "addresses"
else
    say "the run failed; $pkg ($size MiB) holds what it wrote"
fi
exit "$status"
