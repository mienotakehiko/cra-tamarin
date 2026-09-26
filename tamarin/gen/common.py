"""Deterministic source transformations for the cra-tamarin v1.1 theories.
Every replace() asserts exactly one hit so that a silent no-op is impossible."""
import re, sys

def rep(s, old, new, count=1):
    n = s.count(old)
    if n != count:
        sys.exit(f"replace hit {n} times (expected {count}):\n---\n{old}\n---")
    return s.replace(old, new)

def fix_dh_names(s):
    # W1: '$A' vs '~a' clash (Tamarin wellformedness: identifiers differing only in case)
    s = re.sub(r"~a\b", "~ta", s)
    s = re.sub(r"~b\b", "~tb", s)
    return s

COV_OLD_B = '''          Ex m #k. AcceptEntry(V, A, epoch, L, m) @ k & k < i "'''
COV_OLD_F = '''          Ex m #k. AcceptEntry(V, A, epoch, L, m) @ k "'''
COV_NEW   = '''          Ex m #k. AcceptEntry(V, A, epoch, L, m) @ k
                 & (k < i | #k = #i) "'''

BINDING = '''
/* (g) Aggregate binding (added in artefact v1.1)
 *
 *  If the Verifier accepts evidence set evset for session (A, epoch, n)
 *  and A's AIK is not revealed, then A's aggregator actually Quoted
 *  exactly that evidence set, for that Verifier, epoch and nonce.
 *  Coverage (f) says "no honest roster leaf is missing"; binding (g) says
 *  "what the Verifier accepted is what the AIK holder committed to".  The
 *  ablation theories show that (f) needs D1 and D4, and (g) needs D2 and D3.
 */

lemma aggregate_binding:
    " All V A epoch n evset #i.
          Accept(V, A, epoch, evset) @ i
        & AcceptedFrom(V, A, epoch, n) @ i
        & not (Ex #r. RevealedTPM(A) @ r & r < i)
      ==>
          Ex #j. AggrQuoted(A, V, epoch, n, evset) @ j & j < i "

end
'''

def add_binding(s):
    return rep(s, "\nend\n", BINDING)
