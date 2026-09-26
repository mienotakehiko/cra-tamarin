#!/usr/bin/env python3
"""Summarise a Tamarin --output-json counterexample: protocol-rule instances in
topological order, with their action facts."""
import json, sys
from collections import defaultdict
def term(t):
    if isinstance(t, str): return t
    if isinstance(t, dict):
        if 'jgnFactName' in t: pass
    return json.dumps(t)[:80]
for fn in sys.argv[1:]:
    g = json.load(open(fn))['graphs'][0]
    nodes = {n['jgnId']: n for n in g['jgNodes']}
    rules = {i:n for i,n in nodes.items() if n['jgnType']=='isProtocolRule'}
    succ=defaultdict(set); indeg=defaultdict(int)
    for e in g['jgEdges']:
        s=e['jgeSource'].split(':')[0]; t=e['jgeTarget'].split(':')[0]
        if s in rules and t in rules and s!=t and t not in succ[s]:
            succ[s].add(t); indeg[t]+=1
    order=[]; q=sorted([r for r in rules if indeg[r]==0])
    while q:
        r=q.pop(0); order.append(r)
        for t in sorted(succ[r]):
            indeg[t]-=1
            if indeg[t]==0: q.append(t)
    order += [r for r in rules if r not in order]
    print(f"== {fn}: {len(rules)} protocol-rule instances")
    for r in order:
        md=rules[r].get('jgnMetadata',{})
        acts=[a.get('jgnFactShow') or a.get('jgnFactName') for a in md.get('jgnActs',[])] if isinstance(md,dict) else []
        acts=[a for a in acts if a and not a.startswith(('Eq(','Neq('))]
        print(f"  {r:6} {rules[r]['jgnLabel']:34} {'; '.join(acts)[:170]}")
