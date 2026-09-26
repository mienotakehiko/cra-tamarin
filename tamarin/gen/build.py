#!/usr/bin/env python3
"""Generate the v1.1 theory set from the v1.0 sources (tamarin/*.spthy @ 0e1bd11).
Usage: python3 build.py <v1.0 dir> <out dir>
  e.g.  mkdir v10 && for f in baseline fixed fixed_split; do
          git show 0e1bd11:tamarin/$f.spthy > v10/$f.spthy; done
        python3 gen/build.py v10 regen && diff -r regen . (theories only)"""
import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
from common import rep, fix_dh_names, COV_OLD_B, COV_OLD_F, COV_NEW, add_binding

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
rd = lambda f: open(os.path.join(src, f)).read()
def wr(f, s):
    open(os.path.join(out, f), "w").write(s)

# ---------------------------------------------------------------- headers
def header(name, role, body):
    return ("/*\n * " + "="*76 + "\n"
        f" *  {name}\n"
        f" *  cra-tamarin companion artefact v1.1: {role}\n *\n"
        " *  Paper    : Formal Analysis of Hierarchical Collective Remote Attestation\n"
        " *             with Heterogeneous TPM/DICE Roots of Trust in Tamarin Prover\n"
        " *             (T. Mieno, BCE'27, Springer LNNS)\n *\n"
        + "".join(" *  " + l + "\n" if l else " *\n" for l in body.strip("\n").split("\n")) +
        " *\n *  Toolchain: tamarin-prover 1.12.0; cross-checked with maude 3.2 and 3.5.1.\n"
        " *  Expected results: see expected/" + name.replace('.spthy','.txt') + "\n"
        " * " + "="*76 + "\n */\n")

def strip_header(s):
    i = s.index("*/")
    return s[i+2:].lstrip("\n")

LEMMAS = """Lemmas (identical text in every theory of the artefact):
  executability          exists-trace  sanity: an honest run reaches Accept
  key_secrecy            all-traces    TEE-TPM DH key secrecy
  injective_agree_TEE    all-traces    TEE's injective agreement with TPM
  freshness              all-traces    accepted report answers V's challenge
  report_integrity       all-traces    per-leaf integrity of AcceptEntry
  cryptographic_coverage all-traces    no honest roster leaf silently omitted
  aggregate_binding      all-traces    accepted evidence = evidence the AIK
                                       holder Quoted (added in v1.1)"""

COV_WHY_FIXED = """ *      The Verifier's rule reads the committed roster !RosterOf(A, L1, L2)
 *      (D1).  Publish_Roster is the only source of MemberOf and fires once
 *      per aggregator (Unique_Roster), so every member L of A is L1 or L2.
 *      The same atomic rule verifies a fresh DICE signature from each
 *      roster leaf and emits AcceptEntry for BOTH L1 and L2 at the instant
 *      of Accept (D4).  The ablation theories ablation_D{1..4}.spthy
 *      confirm that coverage needs D1 and D4, whereas D2 and D3 are needed
 *      only for aggregate_binding (g)."""

def retitle_cov(s):
    s = rep(s, """/* ---- Cryptographic coverage (should now be PROVED) ----
 *
 *  Statement (informal):
 *      If Verifier accepts""", """/* (f) Cryptographic coverage
 *
 *  Informal statement:
 *      If the Verifier accepts""")
    s = rep(s, """ *      If the Verifier accepts an aggregate for A@epoch and L is a registered
 *      member of A's roster with L neither compromised nor with A's AIK
 *      revealed, then the Verifier has recorded an AcceptEntry for L
 *      in the same session, no later than the Accept itself.""", """ *      If the Verifier accepts an aggregate for A at epoch, L is a
 *      registered member of A's roster, L is not compromised, and A's AIK
 *      is not revealed, then the Verifier has recorded an AcceptEntry for
 *      L in the same session, no later than the Accept itself.""")
    s = rep(s, """ *  Why it holds now:
 *      Accept requires the Quote signature to verify against a payload
 *      that includes h(<L1, L2>).  Because the free-term algebra makes
 *      hashing injective at the symbolic level, the pair <$L1, $L2> in
 *      the Verifier's rule must equal the pair in the Aggregator's rule.
""", """ *  Why it holds in the hardened design:
""")
    i = s.index(" *  Why it holds in the hardened design:")
    j = s.index(" * ------------------------------------------------------------------ */", i)
    return s[:j] + " */" + s[j + len(" * ------------------------------------------------------------------ */"):]

RD = """restriction Roster_Distinct:            /* v1.1: |R(A)| = 2 means two DISTINCT leaves */
    " All x #i. RosterDistinct(x, x) @ i ==> F "

"""

# Comment-only polish of text inherited from v1.0.  Every entry must hit at
# least once across the three sources, so a stale entry cannot pass silently.
POLISH = [
("""/* ---------------------------------------------------------------------------
 *  Abstracted primitives
 *  ------------------------------------------------------------------------
 *  The theories rely on the built-in `sign/verify` and `h/1`; no extra function
 *  symbols are required.  Messages are tagged by string constants ('LEAF_EV', 'AGG_EV',
 *  ...) to keep the different signature contexts disjoint.
 * ------------------------------------------------------------------------- */""",
"""/* ===========================================================================
 *  Abstracted primitives
 *
 *  The theories rely on the built-in sign/verify and h/1 and need no extra
 *  function symbols.  String tags ('LEAF_EV', 'AGG_EV', ...) keep the
 *  different signature contexts disjoint.
 * =========================================================================== */"""),
(""" *  Uniqueness of enrollment is enforced by restrictions.""",
 """ *  Restrictions enforce unique enrollment."""),
("""/* Enrollment authority publishes membership of leaf L in aggregator A.
 * Persistent fact; action Member is recorded for use in the coverage lemma. */""",
"""/* The Enrollment Authority publishes the membership of leaf L in aggregator
 * A.  The persistent fact !Member feeds the protocol rules, and the action
 * MemberOf feeds the coverage lemma.                                       */"""),
(""" *  Both signatures are then bound so that a shared key g^(a*b) is agreed.
 *
 *  NOTE (baseline): the transcript does NOT include the current epoch nor
 *  the challenge nonce.  A cross-session TEE reuse would be conceivable
 *  in more elaborate threat models; here the model keeps this simple and lets the
 *  falsification arise elsewhere (coverage).""",
""" *  Binding both signatures lets the two sides agree on g^(ta*tb).
 *
 *  NOTE (baseline): the transcript includes neither the current epoch nor
 *  the challenge nonce.  Cross-session reuse of a TEE key would be
 *  conceivable in richer threat models; this model keeps the handshake
 *  simple, and the falsification arises elsewhere (coverage)."""),
("""/* ===========================================================================
 *  5. Aggregator: collect leaf evidence, ask TPM to Quote
 * ===========================================================================
 *  BASELINE weakness (deliberate).
 *  --------------------------------
 *  The TPM Quote payload here is
 *
 *      <'AGG_EV', A, V, epoch, n>
 *
 *  and does NOT commit to
 *      (a) the hash of the child-evidence-set actually forwarded, nor
 *      (b) the hash of the expected roster.
 *
 *  This lets a Dolev-Yao adversary silently drop a leaf's LEAF_EV from
 *  the network before the aggregator sees it: the aggregator still
 *  produces a valid Quote for the (V, epoch, n) triple, and the verifier
 *  cannot tell the leaf's evidence is missing.
 *
 *  The rule "Aggregator_Quote" produces the Quote regardless of the
 *  child-evidence set.  The rule records the packed evidence set in an action
 *  ForwardedEvSet so that lemmas can talk about which leaves the
 *  aggregator saw.
 * --------------------------------------------------------------------------- */""",
"""/* ===========================================================================
 *  5. Aggregator: collect leaf evidence, ask TPM to Quote
 *
 *  BASELINE weakness (deliberate).  The TPM Quote payload here is
 *
 *      <'AGG_EV', A, V, epoch, n>
 *
 *  and does NOT commit to
 *      (a) the hash of the child-evidence set actually forwarded, nor
 *      (b) the hash of the expected roster.
 *
 *  A Dolev-Yao adversary can therefore silently drop a leaf's LEAF_EV from
 *  the network before the aggregator sees it: the aggregator still
 *  produces a valid Quote for the (V, epoch, n) triple, and the verifier
 *  cannot tell that the leaf's evidence is missing.
 *
 *  Rule Aggregator_Quote produces the Quote regardless of the
 *  child-evidence set and records that set in the action AggrQuoted, so
 *  that lemmas can refer to the evidence the aggregator forwarded.
 * =========================================================================== */"""),
("""/* ===========================================================================
 *  9. Sources lemma
 *
 *  For each origin of a leaf-attestation signature the model tells Tamarin either
 *  the leaf produced it honestly (LeafAttested action recorded), or the
 *  adversary knew the CDI beforehand (a KU-fact chain).  This resolves the
 *  partial deconstructions triggered by Verifier_ParseEntry pattern-matching
 *  on sign(...) directly out of the network.
 * =========================================================================== */

/* Sources lemma is not required in this model: the verifier's
 * parsing rule already forces signature verification via the `verify`
 * predicate, so Tamarin's constraint solver can trace `AcceptEntry` back
 * to either an honest `LeafAttested` or an adversary-known CDI, both of
 * which the built-in DY solver handles without a manual sources hint.
 * The [sources] lemma is therefore omitted in favour of the automatic
 * partial-deconstruction resolution.                                    */""",
"""/* ===========================================================================
 *  9. Sources lemma (not needed)
 *
 *  The model needs no [sources] lemma.  Verifier_ParseEntry checks each
 *  leaf signature through the verify() equality restriction instead of
 *  pattern-matching on sign(...), so Tamarin's built-in Dolev-Yao solver
 *  traces every AcceptEntry back to either an honest LeafAttested or an
 *  adversary-known CDI and resolves all partial deconstructions
 *  automatically.
 * =========================================================================== */"""),
("""/* ---- (a) Sanity : an honest run reaches Verifier_Accept ---- */""",
 """/* (a) Sanity: an honest run reaches Accept. */"""),
("""/* ---- (b) TEE-TPM session key secrecy ---- */""", """/* (b) TEE-TPM session key secrecy */"""),
("""/* ---- (c) Injective agreement, TEE's view of TPM ---- */""", """/* (c) Injective agreement, TEE's view of TPM */"""),
("""/* ---- (d) Freshness of accepted aggregate reports ---- */""", """/* (d) Freshness of accepted aggregate reports */"""),
("""/* ---- (e) Per-leaf report integrity ---- */""", """/* (e) Per-leaf report integrity */"""),
("""/* ---- (f) Cryptographic coverage : EXPECTED TO FALSIFY ---- *
 *
 *  If a verifier accepts an aggregate for A@epoch and L is a registered
 *  member of A that is *not* compromised, then the verifier must have
 *  parsed a fresh leaf evidence for L in that same session.
 *
 *  In this baseline the aggregator's Quote does not commit to the child
 *  evidence set, so an on-path adversary can drop LEAF_EV(L) between L and
 *  A and the verifier will still Accept.  Tamarin should produce an attack
 *  trace here that is cited as Figure 3 of the paper.
 * --------------------------------------------------------------------- */""",
"""/* (f) Cryptographic coverage: EXPECTED TO FALSIFY
 *
 *  If a verifier accepts an aggregate for A at epoch, L is a registered
 *  member of A that is *not* compromised, and A's AIK is not revealed,
 *  then the verifier must have parsed fresh leaf evidence for L in that
 *  same session, no later than the Accept itself.
 *
 *  In this baseline the aggregator's Quote does not commit to the child
 *  evidence set, so an on-path adversary can drop LEAF_EV(L) between L and
 *  A and the verifier still accepts.  Tamarin finds the silent-omission
 *  trace; Fig. 3 of the paper shows its k = 2 instance.
 */"""),
("""/* D1: Enrollment authority publishes an explicit two-leaf roster.
 *     The two leaves are recorded both individually (for the coverage
 *     lemma to quantify over each) and as an ordered pair (so the
 *     aggregator can compute the same hash the verifier will).          */""",
"""/* D1: The Enrollment Authority publishes an explicit two-leaf roster.
 *     The rule records the two leaves both individually (so that the
 *     coverage lemma can quantify over each) and as an ordered pair (so
 *     that the aggregator computes the same hash as the verifier).       */"""),
("""/* D3/D4: Atomic verification.
 *
 *   In one rule the verifier
 *      (a) recomputes both hashes,
 *      (b) verifies the aggregate signature under AIK,
 *      (c) verifies BOTH leaf signatures under their respective PKs,
 *      (d) emits Accept AND both AcceptEntry actions.
 *
 *   Making it atomic is essential for cryptographic_coverage: coverage
 *   must hold *at the moment Accept fires*, not "eventually".
 */""",
"""/* D3/D4: Atomic verification.
 *
 *   In one rule the verifier
 *      (a) recomputes both hashes,
 *      (b) verifies the aggregate signature under AIK,
 *      (c) verifies BOTH leaf signatures under their respective PKs,
 *      (d) emits Accept AND both AcceptEntry actions.
 *
 *   Gating Accept on every per-leaf check is essential for
 *   cryptographic_coverage: coverage must hold *at the moment Accept
 *   fires*, not "eventually".  This rule achieves the gating atomically;
 *   fixed_split.spthy achieves it with a multi-step state machine.
 */"""),
]
_polish_hits = [0] * len(POLISH)

def common(s):
    s = fix_dh_names(s)
    for i, (old, new) in enumerate(POLISH):
        if old in s:
            _polish_hits[i] += s.count(old)
            s = s.replace(old, new)
    return s

# ---------------------------------------------------------------- baseline
b = strip_header(rd("baseline.spthy"))
b = common(b)
b = rep(b, COV_OLD_B, COV_NEW)
b = rep(b, """ *  then the verifier must have
 *  parsed a fresh leaf evidence for L in that same session.""", """ *  then the verifier must have
 *  parsed a fresh leaf evidence for L in that same session, no later than
 *  the Accept itself.""") if " *  then the verifier must have\n *  parsed" in b else b
b = add_binding(b)
b = header("baseline.spthy", "baseline design (paper Sections 4, 5, 7)", """
Baseline design following the RATS Composite-Attester pattern.  The TPM
Quote payload p_base = <'AGG_EV', A, V, epoch, n> carries the child-evidence
set without binding it, and Accept fires independently of the per-leaf
Verifier_ParseEntry rule.  Publish_Membership registers roster members one
leaf at a time.

""" + LEMMAS + """

Expected: the first five lemmas verified; cryptographic_coverage FALSIFIED
(13-step silent-omission trace, paper Fig. 3); aggregate_binding FALSIFIED
(the evidence set is not under the AIK signature).""") + "\n" + b
wr("baseline.spthy", b)

# ---------------------------------------------------------------- fixed
f = strip_header(rd("fixed.spthy"))
f = common(f)
f = rep(f, "  --[ RosterFixed($A, $L1, $L2),", "  --[ RosterFixed($A, $L1, $L2), RosterDistinct($L1, $L2),")
f = rep(f, "restriction Unique_Roster:", RD + "restriction Unique_Roster:")
f = rep(f, COV_OLD_F, COV_NEW)
f = rep(f, "AggrQuoted($A, $V, epoch, n, $L1, $L2, m1, m2)", "AggrQuoted($A, $V, epoch, n, <m1, m2>)")
f = rep(f, """ *  D2:  The aggregator now MUST receive the actual leaf signatures ev1, ev2
 *       from the two roster members and MUST include
 *           h(<ev1, ev2>)  and  h(<L1, L2>)
 *       in the TPM Quote payload.""", """ *  D2:  The aggregator now MUST receive the actual leaf evidence (m_i, ev_i)
 *       of the two roster members and MUST include
 *           h(<m1, ev1, m2, ev2>)  and  h(<L1, L2>)
 *       in the TPM Quote payload.""")
f = rep(f, """ *  D3, D4:  Verifier recomputes h(<ev1,ev2>) and h(<L1,L2>) itself and
 *           checks the Quote signature over the full payload.  It then
 *           parses each leaf signature (ev1, ev2) individually, so an
 *           AcceptEntry event is emitted per roster member.""", """ *  D3:  The Verifier recomputes h(<m1,ev1,m2,ev2>) and h(<L1,L2>) itself
 *       from the plaintext report and its own !RosterOf, then checks the
 *       Quote signature over the reconstructed payload.
 *  D4:  The AIK check, both DICE checks, Accept and both AcceptEntry
 *       actions occur in ONE rule, so Accept cannot precede an entry.""")
f = rep(f, """ *      Once these are equal, the Verifier's own Parse rules produce
 *      AcceptEntry for BOTH L1 and L2 (using ev1, ev2 which are also
 *      bound into the payload via h(<ev1, ev2>)).""", COV_WHY_FIXED)
f = rep(f, """ *      member of A's roster with L neither compromised nor with A's AIK
 *      revealed, then the Verifier has parsed a fresh AcceptEntry for L
 *      in the same session.""", """ *      member of A's roster with L neither compromised nor with A's AIK
 *      revealed, then the Verifier has recorded an AcceptEntry for L
 *      in the same session, no later than the Accept itself.""")
f = retitle_cov(f)
f = add_binding(f)
FIXED_BODY = """
Hardened design, atomic Verifier (paper Section 8).  Four edits w.r.t.
baseline.spthy, each tagged D1..D4 in the rule comments:
  D1  Publish_Roster: the Endorser commits an ordered roster
      !RosterOf(A, L1, L2) of two distinct leaves, read by both
      aggregator and Verifier.
  D2  Aggregator_Quote_Fixed: the AIK signs
      p_fix = <'AGG_EV', A, V, epoch, n, h(<m1, ev1, m2, ev2>), h(<L1, L2>)>.
  D3  Verifier_AcceptAggregate_Fixed rebuilds both hashes from the
      plaintext report and its own !RosterOf before the AIK check.
  D4  The AIK check, both DICE checks, Accept and both AcceptEntry
      actions are in one rule body.

""" + LEMMAS + """

Expected: all seven lemmas verified."""
f = header("fixed.spthy", "hardened design, atomic Verifier (Section 8)", FIXED_BODY) + "\n" + f
wr("fixed.spthy", f)
fixed_v11 = f

# ---------------------------------------------------------------- fixed_split
s = strip_header(rd("fixed_split.spthy"))
s = common(s)
s = rep(s, "  --[ RosterFixed($A, $L1, $L2),", "  --[ RosterFixed($A, $L1, $L2), RosterDistinct($L1, $L2),")
s = rep(s, "restriction Unique_Roster:", RD + "restriction Unique_Roster:")
s = rep(s, COV_OLD_F, COV_NEW)
s = rep(s, "AggrQuoted($A, $V, epoch, n, $L1, $L2, m1, m2)", "AggrQuoted($A, $V, epoch, n, <m1, m2>)")
s = rep(s, """ *  D2:  The aggregator now MUST receive the actual leaf signatures ev1, ev2
 *       from the two roster members and MUST include
 *           h(<ev1, ev2>)  and  h(<L1, L2>)
 *       in the TPM Quote payload.""", """ *  D2:  The aggregator now MUST receive the actual leaf evidence (m_i, ev_i)
 *       of the two roster members and MUST include
 *           h(<m1, ev1, m2, ev2>)  and  h(<L1, L2>)
 *       in the TPM Quote payload.""")
# replace the stale atomic-rule comment + H2 comment by one accurate block
i0 = s.index(" *  D3, D4:  Verifier recomputes")
i1 = s.index("rule Verifier_ReceiveReport:")
s = s[:i0] + """ *  D3:  Verifier_CheckAIK recomputes both hashes from the carried report
 *       components and the Verifier's own !RosterOf before the AIK check.
 *  D4 (multi-step form): instead of one atomic rule, the Verifier is a
 *       five-rule state machine
 *           ReceiveReport -> CheckAIK -> CheckLeaf_L1 -> CheckLeaf_L2
 *           -> Finalize
 *       connected by linear state facts that carry the full session tuple.
 *       Each rule consumes its state fact exactly once, and only Finalize
 *       emits Accept, i.e. after every per-leaf check.  The partial states
 *       therefore appear explicitly on the trace.
 * =========================================================================== */

""" + s[i1:]
s = rep(s, """ *      Once these are equal, the Verifier's own Parse rules produce
 *      AcceptEntry for BOTH L1 and L2 (using ev1, ev2 which are also
 *      bound into the payload via h(<ev1, ev2>)).""", """ *      Verifier_ReceiveReport reads the committed roster
 *      !RosterOf(A, L1, L2) (D1), and every member L of A is L1 or L2
 *      (Publish_Roster, Unique_Roster).  Finalize, the only rule that emits
 *      Accept, consumes the state produced by both per-leaf checks and
 *      emits AcceptEntry for BOTH L1 and L2 together with Accept.""")
s = rep(s, """ *      member of A's roster with L neither compromised nor with A's AIK
 *      revealed, then the Verifier has parsed a fresh AcceptEntry for L
 *      in the same session.""", """ *      member of A's roster with L neither compromised nor with A's AIK
 *      revealed, then the Verifier has recorded an AcceptEntry for L
 *      in the same session, no later than the Accept itself.""")
s = retitle_cov(s)
s = add_binding(s)
s = header("fixed_split.spthy", "hardened design, multi-step Verifier (Section 8)", """
Same design as fixed.spthy with identical edits D1..D3.  A five-rule state
machine replaces the atomic Verifier rule (D4 in multi-step form), which
shows that coverage is a property of the design rather than of the atomic
modelling choice.

""" + LEMMAS + """

Expected: all seven lemmas verified.""") + "\n" + s
wr("fixed_split.spthy", s)

# ================================================================ ablations
F = strip_header(fixed_v11)
F = rep(F, """ *  Why it holds in the hardened design:""", """ *  ABLATION note: the reasoning below applies to fixed.spthy; the header
 *  of this file gives the expected result for this theory.
 *
 *  Why it holds in the hardened design:""")
ABL_NOTE = """Method: this theory is fixed.spthy with ONE edit reverted.  Apart from the
theory name, every change sits in a line or comment block tagged 'ABLATION'
(check with: diff fixed.spthy {me}), and all seven lemma texts are
identical.  executability stays verified, which rules out a vacuous (dead)
model."""

# ---- D1: no roster commitment (per-leaf membership, as in the baseline)
d1 = rep(F, """/* D1: The Enrollment Authority publishes an explicit two-leaf roster.
 *     The rule records the two leaves both individually (so that the
 *     coverage lemma can quantify over each) and as an ordered pair (so
 *     that the aggregator computes the same hash as the verifier).       */
rule Publish_Roster:
    [ !LtkLeaf($L1, cdi1), !LtkLeaf($L2, cdi2), !LtkTPM($A, aik) ]
  --[ RosterFixed($A, $L1, $L2), RosterDistinct($L1, $L2),
      MemberOf($L1, $A), MemberOf($L2, $A),
      OnlyOnceR($A) ]->
    [ !RosterOf($A, $L1, $L2),
      !Member($L1, $A), !Member($L2, $A) ]""", """/* ABLATION D1: no committed roster.  Publish_Membership registers members
 * one leaf at a time, exactly as in baseline.spthy, and no canonical
 * !RosterOf tuple exists.  Aggregator and Verifier instead accept ANY two
 * distinct members <L1, L2> of A (D2-D4 are otherwise unchanged).      */
rule Publish_Membership:
    [ !LtkLeaf($L, cdi), !LtkTPM($A, aik) ]
  --[ MemberOf($L, $A) ]->
    [ !Member($L, $A) ]""")
d1 = rep(d1, "      !RosterOf($A, $L1, $L2),\n", "      !Member($L1, $A), !Member($L2, $A),  /* ABLATION D1 */\n", count=2)
d1 = rep(d1, """  --[ AggrQuoted($A, $V, epoch, n, <m1, m2>),""", """  --[ AggrQuoted($A, $V, epoch, n, <m1, m2>),
      Neq($L1, $L2),                       /* ABLATION D1 */""")
d1 = rep(d1, """  --[ Eq(verify(sig_agg, payload, pkTpm), true),""", """  --[ Eq(verify(sig_agg, payload, pkTpm), true),
      Neq($L1, $L2),                       /* ABLATION D1 */""")
d1 = rep(d1, RD + """restriction Unique_Roster:
    " All A #i #j. OnlyOnceR(A) @ i & OnlyOnceR(A) @ j ==> #i = #j "
""", """restriction Inequality:            /* ABLATION D1: pairs of DISTINCT members */
    " All x #i. Neq(x, x) @ i ==> F "
""")
d1 = header("ablation_D1.spthy", "ablation: fixed.spthy without D1", """
Reverted edit: D1 (explicit roster commitment).

""" + ABL_NOTE.format(me="ablation_D1.spthy") + """
Note: the pair <L1, L2> is still hashed into the Quote (D2) and rebuilt by
the Verifier (D3), but it is no longer checked against a canonical roster,
so it only commits to "some two members".  The Neq(L1, L2) actions keep the
counterexample from degenerating into a report of the same leaf twice.

Expected: cryptographic_coverage FALSIFIED (an aggregator with three
enrolled members reports two of them and silently omits the third, honest
leaf, so the silent-omission attack reappears despite D2-D4);
aggregate_binding verified; the other five lemmas verified.""") + "\n" + d1
d1 = rep(d1, "theory HierarchicalCRA_Fixed\n", "theory HierarchicalCRA_Ablation_D1\n")
wr("ablation_D1.spthy", d1)

# ---- D2: Quote payload reverted to p_base
PAY = """    let payload = <'AGG_EV', $A, $V, epoch, n,
                   h(<m1, ev1, m2, ev2>), h(<$L1, $L2>)>"""
d2 = rep(F, PAY, """    let payload = <'AGG_EV', $A, $V, epoch, n>   /* ABLATION D2: p_base */""", count=2)
d2 = header("ablation_D2.spthy", "ablation: fixed.spthy without D2", """
Reverted edit: D2 (extended Quote payload).  Both the aggregator and the
Verifier use p_base = <'AGG_EV', A, V, epoch, n>.  With nothing to
reconstruct, D3 becomes vacuous (the Verifier rebuilds p_base only);
D1 and D4 are intact.

""" + ABL_NOTE.format(me="ablation_D2.spthy") + """

Expected: cryptographic_coverage VERIFIED (D1 + D4 alone suffice: the
atomic rule still checks a DICE signature for every roster leaf);
aggregate_binding FALSIFIED (the Verifier accepts a mix of per-session
leaf evidence that the AIK holder never Quoted);
the other five lemmas verified.""") + "\n" + d2
d2 = rep(d2, "theory HierarchicalCRA_Fixed\n", "theory HierarchicalCRA_Ablation_D2\n")
d2 = rep(d2, """ *  D2:  The aggregator now MUST receive the actual leaf evidence (m_i, ev_i)""",
""" *  ABLATION D2: this theory reverts D2; the payload lines tagged ABLATION
 *  below use p_base, and the rest of this block describes fixed.spthy.
 *
 *  D2:  The aggregator now MUST receive the actual leaf evidence (m_i, ev_i)""")
wr("ablation_D2.spthy", d2)

# ---- D3: Verifier does not reconstruct; takes the two digests from the report
d3 = rep(F, """            $L1, $L2, m1, ev1, m2, ev2,
            sign(payload, aik) >) ]""", """            $L1, $L2, m1, ev1, m2, ev2,
            h(<m1, ev1, m2, ev2>), h(<$L1, $L2>),   /* ABLATION D3: digests shipped */
            sign(payload, aik) >) ]""")
d3 = rep(d3, """rule Verifier_AcceptAggregate_Fixed:
""" + PAY, """rule Verifier_AcceptAggregate_Fixed:
    /* ABLATION D3: the Verifier does NOT recompute the digests; it checks
     * the AIK signature over the digests hev, hro carried in the report. */
    let payload = <'AGG_EV', $A, $V, epoch, n, hev, hro>""")
d3 = rep(d3, """           $L1, $L2, m1, ev1, m2, ev2, sig_agg >) ]""", """           $L1, $L2, m1, ev1, m2, ev2, hev, hro, sig_agg >) ]   /* ABLATION D3 */""")
d3 = header("ablation_D3.spthy", "ablation: fixed.spthy without D3", """
Reverted edit: D3 (Verifier-side reconstruction).  The aggregator still
Quotes p_fix (D2) and additionally ships the two digests in the report;
the Verifier checks the AIK signature over the SHIPPED digests instead of
recomputing them from (L1, L2, m1, ev1, m2, ev2).  D1, D2, D4 intact.

""" + ABL_NOTE.format(me="ablation_D3.spthy") + """

Expected: cryptographic_coverage VERIFIED (D1 + D4 suffice);
aggregate_binding FALSIFIED (the plaintext evidence is decoupled from the
Quoted digest, so D2's commitment is never enforced);
the other five lemmas verified.""") + "\n" + d3
d3 = rep(d3, "theory HierarchicalCRA_Fixed\n", "theory HierarchicalCRA_Ablation_D3\n")
d3 = rep(d3, """ *  D3:  The Verifier recomputes h(<m1,ev1,m2,ev2>) and h(<L1,L2>) itself""",
""" *  ABLATION D3: this theory reverts D3 (see the rule comment below); the
 *  D3 description that follows applies to fixed.spthy.
 *
 *  D3:  The Verifier recomputes h(<m1,ev1,m2,ev2>) and h(<L1,L2>) itself""")
wr("ablation_D3.spthy", d3)

# ---- D4: non-atomic acceptance (Accept after AIK check; per-leaf rules separate)
i0 = F.index("/* D3/D4: Atomic verification.")
i1 = F.index("/* ===========================================================================\n *  7.")
d4 = F[:i0] + """/* ABLATION D4: non-atomic acceptance (the "earlier iteration" of Sec. 8).
 *   Verifier_AcceptAggregate_NA performs D3 and the AIK check and emits
 *   Accept.  Two separate per-leaf rules over the same report perform the
 *   DICE checks and emit AcceptEntry, and neither is a precondition of
 *   Accept.  D1-D3 are unchanged.                                        */
rule Verifier_AcceptAggregate_NA:
""" + PAY + """
    in
    [ !Session($V, $A, n, epoch),
      !PkTPM($A, pkTpm),
      !RosterOf($A, $L1, $L2),
      In(< 'AGG_REPORT', $A, $V, epoch,
           $L1, $L2, m1, ev1, m2, ev2, sig_agg >) ]
  --[ Eq(verify(sig_agg, payload, pkTpm), true),
      Accept($V, $A, epoch, <m1, m2>),
      AcceptedFrom($V, $A, epoch, n) ]->
    [ ]

rule Verifier_ParseEntry_L1:
""" + PAY + """
    in
    [ !Session($V, $A, n, epoch),
      !PkTPM($A, pkTpm),
      !PkLeaf($L1, pkL1),
      !RosterOf($A, $L1, $L2),
      In(< 'AGG_REPORT', $A, $V, epoch,
           $L1, $L2, m1, ev1, m2, ev2, sig_agg >) ]
  --[ Eq(verify(sig_agg, payload, pkTpm), true),
      Eq(verify(ev1, <'LEAF_EV', $L1, $A, $V, epoch, n, m1>, pkL1), true),
      AcceptEntry($V, $A, epoch, $L1, m1) ]->
    [ ]

rule Verifier_ParseEntry_L2:
""" + PAY + """
    in
    [ !Session($V, $A, n, epoch),
      !PkTPM($A, pkTpm),
      !PkLeaf($L2, pkL2),
      !RosterOf($A, $L1, $L2),
      In(< 'AGG_REPORT', $A, $V, epoch,
           $L1, $L2, m1, ev1, m2, ev2, sig_agg >) ]
  --[ Eq(verify(sig_agg, payload, pkTpm), true),
      Eq(verify(ev2, <'LEAF_EV', $L2, $A, $V, epoch, n, m2>, pkL2), true),
      AcceptEntry($V, $A, epoch, $L2, m2) ]->
    [ ]


""" + F[i1:]
d4 = header("ablation_D4.spthy", "ablation: fixed.spthy without D4", """
Reverted edit: D4 (atomic / gated acceptance).  Accept fires after the
AIK check over the reconstructed p_fix; per-leaf DICE checks and
AcceptEntry live in separate rules that do not gate Accept.  D1-D3 intact.
Contrast with fixed_split.spthy, which is also multi-step but emits Accept
only after both per-leaf checks: gating, not atomicity per se, is what D4
must provide.

""" + ABL_NOTE.format(me="ablation_D4.spthy") + """

Expected: cryptographic_coverage FALSIFIED (Accept fires with no
AcceptEntry for an honest roster leaf); aggregate_binding verified;
the other five lemmas verified.""") + "\n" + d4
d4 = rep(d4, "theory HierarchicalCRA_Fixed\n", "theory HierarchicalCRA_Ablation_D4\n")
d4 = rep(d4, """ *  D4:  The AIK check, both DICE checks, Accept and both AcceptEntry
 *       actions occur in ONE rule, so Accept cannot precede an entry.""",
""" *  D4:  The AIK check, both DICE checks, Accept and both AcceptEntry
 *       actions occur in ONE rule, so Accept cannot precede an entry.
 *       ABLATION D4: this theory reverts D4 (see the rule comment below).""")
wr("ablation_D4.spthy", d4)
print("ok")

# ================================================================ k = 3
K3_NOTE = """k = 3 instance, obtained from the k = 2 theory by the mechanical lifting
described in Section 5 of the paper: every roster-indexed position
(L_i, m_i, ev_i, pkL_i, DICE check, AcceptEntry) gets a third copy.  The
lifting adds, removes or reorders no rule and leaves every lemma text
unchanged."""

RD3 = RD.replace("/* v1.1: |R(A)| = 2 means two DISTINCT leaves */",
                 "/* v1.1: |R(A)| = 3 means three DISTINCT leaves */")

def lift_fixed_k3(F):
    r = F
    r = rep(r, """rule Publish_Roster:
    [ !LtkLeaf($L1, cdi1), !LtkLeaf($L2, cdi2), !LtkTPM($A, aik) ]
  --[ RosterFixed($A, $L1, $L2), RosterDistinct($L1, $L2),
      MemberOf($L1, $A), MemberOf($L2, $A),
      OnlyOnceR($A) ]->
    [ !RosterOf($A, $L1, $L2),
      !Member($L1, $A), !Member($L2, $A) ]""", """rule Publish_Roster:
    [ !LtkLeaf($L1, cdi1), !LtkLeaf($L2, cdi2), !LtkLeaf($L3, cdi3),
      !LtkTPM($A, aik) ]
  --[ RosterFixed($A, $L1, $L2, $L3),
      RosterDistinct($L1, $L2), RosterDistinct($L1, $L3),
      RosterDistinct($L2, $L3),
      MemberOf($L1, $A), MemberOf($L2, $A), MemberOf($L3, $A),
      OnlyOnceR($A) ]->
    [ !RosterOf($A, $L1, $L2, $L3),
      !Member($L1, $A), !Member($L2, $A), !Member($L3, $A) ]""")
    r = rep(r, "h(<m1, ev1, m2, ev2>), h(<$L1, $L2>)>", "h(<m1, ev1, m2, ev2, m3, ev3>), h(<$L1, $L2, $L3>)>", count=2)
    r = rep(r, "      !RosterOf($A, $L1, $L2),\n", "      !RosterOf($A, $L1, $L2, $L3),\n", count=2)
    r = rep(r, """      In(<'LEAF_EV', $L2, $A, m2, ev2>) ]""", """      In(<'LEAF_EV', $L2, $A, m2, ev2>),
      In(<'LEAF_EV', $L3, $A, m3, ev3>) ]""")
    r = rep(r, "AggrQuoted($A, $V, epoch, n, <m1, m2>)", "AggrQuoted($A, $V, epoch, n, <m1, m2, m3>)")
    r = rep(r, """            $L1, $L2, m1, ev1, m2, ev2,
            sign(payload, aik) >) ]""", """            $L1, $L2, $L3, m1, ev1, m2, ev2, m3, ev3,
            sign(payload, aik) >) ]""")
    r = rep(r, """      !PkLeaf($L2, pkL2),
      !RosterOf""", """      !PkLeaf($L2, pkL2),
      !PkLeaf($L3, pkL3),
      !RosterOf""")
    r = rep(r, """           $L1, $L2, m1, ev1, m2, ev2, sig_agg >) ]""", """           $L1, $L2, $L3, m1, ev1, m2, ev2, m3, ev3, sig_agg >) ]""")
    r = rep(r, """      Eq(verify(ev2, <'LEAF_EV', $L2, $A, $V, epoch, n, m2>, pkL2), true),
      Accept($V, $A, epoch, <m1, m2>),""", """      Eq(verify(ev2, <'LEAF_EV', $L2, $A, $V, epoch, n, m2>, pkL2), true),
      Eq(verify(ev3, <'LEAF_EV', $L3, $A, $V, epoch, n, m3>, pkL3), true),
      Accept($V, $A, epoch, <m1, m2, m3>),""")
    r = rep(r, """      AcceptEntry($V, $A, epoch, $L2, m2) ]->""", """      AcceptEntry($V, $A, epoch, $L2, m2),
      AcceptEntry($V, $A, epoch, $L3, m3) ]->""")
    r = rep(r, "theory HierarchicalCRA_Fixed\n", "theory HierarchicalCRA_Fixed_K3\n")
    # comments that mention the roster size
    r = rep(r, """/* D1: The Enrollment Authority publishes an explicit two-leaf roster.
 *     The rule records the two leaves both individually (so that the
 *     coverage lemma can quantify over each) and as an ordered pair (so
 *     that the aggregator computes the same hash as the verifier).       */""", """/* D1: The Enrollment Authority publishes an explicit three-leaf roster.
 *     The rule records the three leaves both individually (so that the
 *     coverage lemma can quantify over each) and as an ordered triple (so
 *     that the aggregator computes the same hash as the verifier).       */""")
    r = rep(r, """ *       of the two roster members and MUST include
 *           h(<m1, ev1, m2, ev2>)  and  h(<L1, L2>)""", """ *       of the three roster members and MUST include
 *           h(<m1, ev1, m2, ev2, m3, ev3>)  and  h(<L1, L2, L3>)""")
    r = rep(r, """ *  hash commitment forces the adversary either to know both signatures
 *  (which requires both leaves to have actually produced them) or to""", """ *  hash commitment forces the adversary either to know all three signatures
 *  (which requires all three leaves to have actually produced them) or to""")
    r = rep(r, """ *  D3:  The Verifier recomputes h(<m1,ev1,m2,ev2>) and h(<L1,L2>) itself""", """ *  D3:  The Verifier recomputes h(<m1,ev1,m2,ev2,m3,ev3>) and h(<L1,L2,L3>)""")
    r = rep(r, """ *  D4:  The AIK check, both DICE checks, Accept and both AcceptEntry
 *       actions occur in ONE rule, so Accept cannot precede an entry.""", """ *  D4:  The AIK check, all three DICE checks, Accept and all three
 *       AcceptEntry actions occur in ONE rule, so Accept cannot precede an
 *       entry.""")
    r = rep(r, """ *      (c) verifies BOTH leaf signatures under their respective PKs,
 *      (d) emits Accept AND both AcceptEntry actions.""", """ *      (c) verifies ALL three leaf signatures under their respective PKs,
 *      (d) emits Accept AND all three AcceptEntry actions.""")
    r = rep(r, RD, RD3)
    r = rep(r, COV_WHY_FIXED, """ *      The Verifier's rule reads the committed roster
 *      !RosterOf(A, L1, L2, L3) (D1).  Publish_Roster is the only source of
 *      MemberOf and fires once per aggregator (Unique_Roster), so every
 *      member L of A is L1, L2 or L3.  The same atomic rule verifies a
 *      fresh DICE signature from each roster leaf and emits AcceptEntry
 *      for all three leaves at the instant of Accept (D4).""")
    return r

k3 = lift_fixed_k3(strip_header(fixed_v11))
k3 = header("fixed_k3.spthy", "hardened design, atomic Verifier, k = 3 (Section 5)", K3_NOTE + """

""" + LEMMAS + """

Expected: all seven lemmas verified.
Resources: about 20 s and < 1.7 GB RAM with `+RTS -N1 -M1700m -RTS`
(run_all.sh passes these flags); without the heap cap the GHC runtime may
over-allocate on small (2 GB) hosts.""") + "\n" + k3
wr("fixed_k3.spthy", k3)

bk = strip_header(open(os.path.join(out, "baseline.spthy")).read())
bk = rep(bk, """/* The Enrollment Authority publishes the membership of leaf L in aggregator
 * A.  The persistent fact !Member feeds the protocol rules, and the action
 * MemberOf feeds the coverage lemma.                                       */
rule Publish_Membership:
    [ !LtkLeaf($L, cdi), !LtkTPM($A, aik) ]
  --[ MemberOf($L, $A) ]->
    [ !Member($L, $A) ]""", """/* k = 3: the Enrollment authority publishes the membership of exactly
 * three distinct leaves of A in one step (once per A).  The baseline
 * Quote payload and the split Verifier are unchanged.                  */
rule Publish_Membership_K3:
    [ !LtkLeaf($L1, cdi1), !LtkLeaf($L2, cdi2), !LtkLeaf($L3, cdi3),
      !LtkTPM($A, aik) ]
  --[ RosterDistinct($L1, $L2), RosterDistinct($L1, $L3),
      RosterDistinct($L2, $L3),
      MemberOf($L1, $A), MemberOf($L2, $A), MemberOf($L3, $A),
      OnlyOnceR($A) ]->
    [ !Member($L1, $A), !Member($L2, $A), !Member($L3, $A) ]""")
bk = rep(bk, """restriction Unique_Epoch:""", RD3 + """restriction Unique_Roster:
    " All A #i #j. OnlyOnceR(A) @ i & OnlyOnceR(A) @ j ==> #i = #j "

restriction Unique_Epoch:""")
bk = rep(bk, "theory HierarchicalCRA_Baseline\n", "theory HierarchicalCRA_Baseline_K3\n")
bk = header("baseline_k3.spthy", "baseline design, k = 3 (Section 5)", """
Baseline with a roster of exactly three distinct leaves per aggregator.
Everything else (p_base Quote payload, Accept independent of the per-leaf
ParseEntry rule) is identical to baseline.spthy.  The theory shows that the
silent-omission attack is not an artefact of k = 2.

""" + LEMMAS + """

Expected: the first five lemmas verified; cryptographic_coverage and
aggregate_binding FALSIFIED.""") + "\n" + bk
wr("baseline_k3.spthy", bk)
for i, n in enumerate(_polish_hits):
    if n == 0:
        sys.exit("POLISH entry %d never matched" % i)
print("k3 ok")
