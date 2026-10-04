---- MODULE DeliveryService_TTrace_1791133605 ----
EXTENDS DeliveryService_TEConstants, Sequences, TLCExt, DeliveryService, Toolbox, Naturals, TLC

_expression ==
    LET DeliveryService_TEExpression == INSTANCE DeliveryService_TEExpression
    IN DeliveryService_TEExpression!expression
----

_trace ==
    LET DeliveryService_TETrace == INSTANCE DeliveryService_TETrace
    IN DeliveryService_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        hist = ((c1 :> <<[author |-> c1, base |-> 0, n |-> 0]>> @@ c2 :> <<>> @@ c3 :> <<>>))
        /\
        replies = ({[cm |-> [author |-> c1, base |-> 0, n |-> 0], to |-> c1, ok |-> TRUE], [cm |-> [author |-> c2, base |-> 0, n |-> 0], to |-> c2, ok |-> TRUE]})
        /\
        log = (<<[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]>>)
        /\
        pending = ((c1 :> [author |-> "none", base |-> 0, n |-> 0] @@ c2 :> [author |-> c2, base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]))
        /\
        srvEpoch = (1)
        /\
        cnt = ((c1 :> 1 @@ c2 :> 1 @@ c3 :> 0))
        /\
        net = ({})
        /\
        acked = ({[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]})
        /\
        seen = ((c1 :> {1} @@ c2 :> {} @@ c3 :> {}))
    )
----

_init ==
    /\ pending = _TETrace[1].pending
    /\ seen = _TETrace[1].seen
    /\ replies = _TETrace[1].replies
    /\ net = _TETrace[1].net
    /\ srvEpoch = _TETrace[1].srvEpoch
    /\ cnt = _TETrace[1].cnt
    /\ hist = _TETrace[1].hist
    /\ log = _TETrace[1].log
    /\ acked = _TETrace[1].acked
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ pending  = _TETrace[i].pending
        /\ pending' = _TETrace[j].pending
        /\ seen  = _TETrace[i].seen
        /\ seen' = _TETrace[j].seen
        /\ replies  = _TETrace[i].replies
        /\ replies' = _TETrace[j].replies
        /\ net  = _TETrace[i].net
        /\ net' = _TETrace[j].net
        /\ srvEpoch  = _TETrace[i].srvEpoch
        /\ srvEpoch' = _TETrace[j].srvEpoch
        /\ cnt  = _TETrace[i].cnt
        /\ cnt' = _TETrace[j].cnt
        /\ hist  = _TETrace[i].hist
        /\ hist' = _TETrace[j].hist
        /\ log  = _TETrace[i].log
        /\ log' = _TETrace[j].log
        /\ acked  = _TETrace[i].acked
        /\ acked' = _TETrace[j].acked

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("DeliveryService_TTrace_1791133605.json", _TETrace)

=============================================================================

 Note that you can extract this module `DeliveryService_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `DeliveryService_TEExpression.tla` file takes precedence 
  over the module `DeliveryService_TEExpression` below).

---- MODULE DeliveryService_TEExpression ----
EXTENDS DeliveryService_TEConstants, Sequences, TLCExt, DeliveryService, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `DeliveryService` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        pending |-> pending
        ,seen |-> seen
        ,replies |-> replies
        ,net |-> net
        ,srvEpoch |-> srvEpoch
        ,cnt |-> cnt
        ,hist |-> hist
        ,log |-> log
        ,acked |-> acked
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_pendingUnchanged |-> pending = pending'
        
        \* Format the `pending` variable as Json value.
        \* ,_pendingJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(pending)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_pendingModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].pending # _TETrace[s-1].pending
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE DeliveryService_TETrace ----
\*EXTENDS DeliveryService_TEConstants, IOUtils, DeliveryService, TLC
\*
\*trace == IODeserialize("DeliveryService_TTrace_1791133605.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE DeliveryService_TETrace ----
EXTENDS DeliveryService_TEConstants, DeliveryService, TLC

trace == 
    <<
    ([hist |-> (c1 :> <<>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {},log |-> <<>>,pending |-> (c1 :> [author |-> "none", base |-> 0, n |-> 0] @@ c2 :> [author |-> "none", base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 0,cnt |-> (c1 :> 0 @@ c2 :> 0 @@ c3 :> 0),net |-> {},acked |-> {},seen |-> (c1 :> {} @@ c2 :> {} @@ c3 :> {})]),
    ([hist |-> (c1 :> <<>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {},log |-> <<>>,pending |-> (c1 :> [author |-> c1, base |-> 0, n |-> 0] @@ c2 :> [author |-> "none", base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 0,cnt |-> (c1 :> 1 @@ c2 :> 0 @@ c3 :> 0),net |-> {[author |-> c1, base |-> 0, n |-> 0]},acked |-> {},seen |-> (c1 :> {} @@ c2 :> {} @@ c3 :> {})]),
    ([hist |-> (c1 :> <<>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {[cm |-> [author |-> c1, base |-> 0, n |-> 0], to |-> c1, ok |-> TRUE]},log |-> <<[author |-> c1, base |-> 0, n |-> 0]>>,pending |-> (c1 :> [author |-> c1, base |-> 0, n |-> 0] @@ c2 :> [author |-> "none", base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 1,cnt |-> (c1 :> 1 @@ c2 :> 0 @@ c3 :> 0),net |-> {},acked |-> {[author |-> c1, base |-> 0, n |-> 0]},seen |-> (c1 :> {} @@ c2 :> {} @@ c3 :> {})]),
    ([hist |-> (c1 :> <<>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {[cm |-> [author |-> c1, base |-> 0, n |-> 0], to |-> c1, ok |-> TRUE]},log |-> <<[author |-> c1, base |-> 0, n |-> 0]>>,pending |-> (c1 :> [author |-> c1, base |-> 0, n |-> 0] @@ c2 :> [author |-> c2, base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 1,cnt |-> (c1 :> 1 @@ c2 :> 1 @@ c3 :> 0),net |-> {[author |-> c2, base |-> 0, n |-> 0]},acked |-> {[author |-> c1, base |-> 0, n |-> 0]},seen |-> (c1 :> {} @@ c2 :> {} @@ c3 :> {})]),
    ([hist |-> (c1 :> <<>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {[cm |-> [author |-> c1, base |-> 0, n |-> 0], to |-> c1, ok |-> TRUE], [cm |-> [author |-> c2, base |-> 0, n |-> 0], to |-> c2, ok |-> TRUE]},log |-> <<[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]>>,pending |-> (c1 :> [author |-> c1, base |-> 0, n |-> 0] @@ c2 :> [author |-> c2, base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 1,cnt |-> (c1 :> 1 @@ c2 :> 1 @@ c3 :> 0),net |-> {},acked |-> {[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]},seen |-> (c1 :> {} @@ c2 :> {} @@ c3 :> {})]),
    ([hist |-> (c1 :> <<[author |-> c1, base |-> 0, n |-> 0]>> @@ c2 :> <<>> @@ c3 :> <<>>),replies |-> {[cm |-> [author |-> c1, base |-> 0, n |-> 0], to |-> c1, ok |-> TRUE], [cm |-> [author |-> c2, base |-> 0, n |-> 0], to |-> c2, ok |-> TRUE]},log |-> <<[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]>>,pending |-> (c1 :> [author |-> "none", base |-> 0, n |-> 0] @@ c2 :> [author |-> c2, base |-> 0, n |-> 0] @@ c3 :> [author |-> "none", base |-> 0, n |-> 0]),srvEpoch |-> 1,cnt |-> (c1 :> 1 @@ c2 :> 1 @@ c3 :> 0),net |-> {},acked |-> {[author |-> c1, base |-> 0, n |-> 0], [author |-> c2, base |-> 0, n |-> 0]},seen |-> (c1 :> {1} @@ c2 :> {} @@ c3 :> {})])
    >>
----


=============================================================================

---- MODULE DeliveryService_TEConstants ----
EXTENDS DeliveryService

CONSTANTS c1, c2, c3

=============================================================================

---- CONFIG DeliveryService_TTrace_1791133605 ----
CONSTANTS
    Clients = { c1 , c2 , c3 }
    MaxCommits = 1
    Fenced = FALSE
    Ordered = TRUE
    MergeOnAccept = FALSE
    c1 = c1
    c3 = c3
    c2 = c2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sun Oct 04 10:06:47 PDT 2026