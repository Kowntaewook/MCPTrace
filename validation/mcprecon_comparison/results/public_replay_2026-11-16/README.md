# Full public-input replay, 2026-11-16

The 27 per-image JSON reports and `replayed-totals.json` were regenerated with
[`replay_all_public.py`](../../replay_all_public.py), using the published
[synthetic traffic journals](../../ground_truth/README.md), the 27 archived
[RAM assets](../../../linux_x64_http_ram/README.md), the pinned MCPTrace source,
Volatility 3, and the pinned public MCPRecon CLI. Local archive copies had the
same SHA-256 values as the published release manifest; the GitHub release API
listed all 27 assets with matching sizes and SHA-256 digests. Each reconstructed
raw image was checked against its published image SHA-256 before scanning.

For every capture, the replay independently probed exact wire-byte presence in
the current client process, reread each MCPTrace record at its process virtual
address, and verified each MCPRecon record at the offset of the derived
client-byte stream. Each per-image result was checked against the prior
capture-level numeric reference. The final aggregate was:

| Measure | Count |
| --- | ---: |
| Externally logged messages | 342 |
| Exact wire bytes in readable client memory | 251 |
| MCPTrace distinct messages carved | 251 |
| MCPTrace address-verified records | 626 |
| MCPRecon distinct messages carved from derived client bytes | 184 |
| MCPRecon offset-verified records | 315 |

The MCP label counts were 233 and 94 distinct logged messages, respectively;
these are classification outputs under different rules. Neither 251/342 nor
184/342 is a general detection rate. MCPRecon's 184 is from the specified
derived client-byte stream, not its native whole-RAM workflow. All files here
contain counts and hashes only. They contain no RAM bytes, recovered messages,
or guest secrets. The separate four-image live-host RAM experiment is outside
this replay and remains privately archived.

The `node-d30-r2.json` report also includes `worked_case_verified: true`.
Its [case note](../../ground_truth/worked_case_node_d30_r2.md) explains the
address reread, external wire match, and exact-wire-absent request. This extra
field does not change the 27-image aggregate.
