--------------------------- MODULE DeliveryService ---------------------------
(***************************************************************************)
(* Commit ordering and epoch fencing in the MLSChat delivery service.      *)
(*                                                                         *)
(* Clients stage commits on top of the epoch they are in and send them.    *)
(* The server appends accepted commits to one log per group. Requests may  *)
(* be retried any number of times (the client re-sends after a dropped     *)
(* connection or a server crash), and replies may be lost. Clients apply   *)
(* the log in order and skip any commit that was built on an epoch they    *)
(* already left.                                                           *)
(*                                                                         *)
(* Knobs:                                                                  *)
(*   Fenced         accept a commit only if it was built on the current    *)
(*                  epoch (the real server); otherwise accept everything.  *)
(*   Ordered        clients see one log order (the real server); FALSE     *)
(*                  models a relay where each client sees its own order.   *)
(*   MergeOnAccept  a client applies its own commit as soon as the server  *)
(*                  acknowledges it, instead of when it meets it in the    *)
(*                  log.                                                   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS Clients, MaxCommits, Fenced, Ordered, MergeOnAccept

VARIABLES
    log,        \* the server's ordered log of accepted commits
    srvEpoch,   \* the epoch the server expects the next commit to build on
    hist,       \* hist[c]: the commits client c has applied, in order
    pending,    \* pending[c]: c's staged commit, or NoCommit
    seen,       \* seen[c]: log positions client c has handled
    cnt,        \* cnt[c]: commits c has staged so far (makes ids unique)
    net,        \* commit requests in flight
    replies,    \* server replies in flight
    acked       \* commits the server acknowledged as accepted

vars == <<log, srvEpoch, hist, pending, seen, cnt, net, replies, acked>>

NoCommit == [author |-> "none", base |-> 0, n |-> 0]

Max(a, b) == IF a > b THEN a ELSE b

InLog(cm) == \E i \in 1..Len(log) : log[i] = cm

Init ==
    /\ log = << >>
    /\ srvEpoch = 0
    /\ hist = [c \in Clients |-> << >>]
    /\ pending = [c \in Clients |-> NoCommit]
    /\ seen = [c \in Clients |-> {}]
    /\ cnt = [c \in Clients |-> 0]
    /\ net = {}
    /\ replies = {}
    /\ acked = {}

\* Client c stages a commit on top of its current epoch and sends it.
Stage(c) ==
    /\ pending[c] = NoCommit
    /\ cnt[c] < MaxCommits
    /\ LET cm == [author |-> c, base |-> Len(hist[c]), n |-> cnt[c]] IN
         /\ pending' = [pending EXCEPT ![c] = cm]
         /\ net' = net \cup {cm}
    /\ cnt' = [cnt EXCEPT ![c] = @ + 1]
    /\ UNCHANGED <<log, srvEpoch, hist, seen, replies, acked>>

\* After a lost reply or a reconnect, the client re-sends the same request.
Resend(c) ==
    /\ pending[c] # NoCommit
    /\ net' = net \cup {pending[c]}
    /\ UNCHANGED <<log, srvEpoch, hist, pending, seen, cnt, replies, acked>>

\* The server handles one request. A request already in the log gets the
\* same answer again (idempotency), so a retry never appends twice.
Serve(cm) ==
    /\ cm \in net
    /\ net' = net \ {cm}
    /\ IF InLog(cm) THEN
          /\ replies' = replies \cup {[to |-> cm.author, cm |-> cm, ok |-> TRUE]}
          /\ UNCHANGED <<log, srvEpoch, acked>>
       ELSE IF ~Fenced \/ cm.base = srvEpoch THEN
          /\ log' = Append(log, cm)
          /\ srvEpoch' = IF Fenced THEN srvEpoch + 1 ELSE Max(srvEpoch, cm.base + 1)
          /\ acked' = acked \cup {cm}
          /\ replies' = replies \cup {[to |-> cm.author, cm |-> cm, ok |-> TRUE]}
       ELSE
          /\ replies' = replies \cup {[to |-> cm.author, cm |-> cm, ok |-> FALSE]}
          /\ UNCHANGED <<log, srvEpoch, acked>>
    /\ UNCHANGED <<hist, pending, seen, cnt>>

\* Replies can be lost (server crash, dropped connection).
LoseReply(r) ==
    /\ r \in replies
    /\ replies' = replies \ {r}
    /\ UNCHANGED <<log, srvEpoch, hist, pending, seen, cnt, net, acked>>

\* The client reads a reply to its pending commit.
Reply(r) ==
    /\ r \in replies
    /\ replies' = replies \ {r}
    /\ LET c == r.to IN
         IF pending[c] = r.cm THEN
            IF ~r.ok THEN
               /\ pending' = [pending EXCEPT ![c] = NoCommit]
               /\ UNCHANGED hist
            ELSE IF MergeOnAccept THEN
               /\ hist' = [hist EXCEPT ![c] = Append(@, r.cm)]
               /\ pending' = [pending EXCEPT ![c] = NoCommit]
            ELSE UNCHANGED <<hist, pending>>
         ELSE UNCHANGED <<hist, pending>>
    /\ UNCHANGED <<log, srvEpoch, seen, cnt, net, acked>>

\* The client handles log position i: the next one if the log is ordered,
\* any unseen one in a relay.
Apply(c, i) ==
    /\ i \in 1..Len(log)
    /\ i \notin seen[c]
    /\ Ordered => i = Cardinality(seen[c]) + 1
    /\ seen' = [seen EXCEPT ![c] = @ \cup {i}]
    /\ LET e == log[i] IN
         IF e.base = Len(hist[c]) /\ ~(\E k \in 1..Len(hist[c]) : hist[c][k] = e) THEN
            \* Built on our epoch: apply it. Any staged commit of ours is now
            \* either this one (merged) or superseded (dropped).
            /\ hist' = [hist EXCEPT ![c] = Append(@, e)]
            /\ pending' = [pending EXCEPT ![c] = NoCommit]
         ELSE UNCHANGED <<hist, pending>>   \* stale, or our own already merged
    /\ UNCHANGED <<log, srvEpoch, cnt, net, replies, acked>>

Next ==
    \/ \E c \in Clients : Stage(c) \/ Resend(c)
    \/ \E cm \in net : Serve(cm)
    \/ \E r \in replies : Reply(r) \/ LoseReply(r)
    \/ \E c \in Clients, i \in 1..Len(log) : Apply(c, i)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
IsPrefix(s, t) == Len(s) <= Len(t) /\ SubSeq(t, 1, Len(s)) = s

\* No fork: any two members' histories agree on every epoch both reached.
NoFork == \A a, b \in Clients : IsPrefix(hist[a], hist[b]) \/ IsPrefix(hist[b], hist[a])

\* An acknowledgement means the commit took effect: every member that reaches
\* that epoch applies exactly that commit there. A committer (and anyone it
\* sent a Welcome to) relies on this.
AckMeansApplied ==
    \A cm \in acked : \A c \in Clients :
        Len(hist[c]) > cm.base => hist[c][cm.base + 1] = cm

\* Retries never put the same commit in the log twice.
NoDuplicateInLog == \A i, j \in 1..Len(log) : i # j => log[i] # log[j]

TypeOK ==
    /\ srvEpoch \in Nat
    /\ \A c \in Clients : cnt[c] \in 0..MaxCommits
ClientSymmetry == Permutations(Clients)
=============================================================================
