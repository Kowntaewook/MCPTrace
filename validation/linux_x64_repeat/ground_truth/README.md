# Exact synthetic wire logs for the Linux repeat experiment

The [manifest](manifest.json) links nine byte-identical non-Codex journals to
their capture IDs, image hashes, PIDs, and public numeric reports. Together
they contain **53 exact JSON bodies**: three Inspector HTTP/SSE journals
(including a separate timing pilot), two Inspector stdio journals, two LSP
controls, and two ordinary JSON-RPC controls. The Inspector data uses
synthetic `echo_marker` arguments. HTTP SSE `data:` prefixes and LSP
`Content-Length` framing bytes are not part of the stored JSON bodies.

[`prepare_public.py`](prepare_public.py) decoded every base64 body, checked it
against its parsed message and the report's per-message SHA-256, and applied a
fixed field/string allowlist and run-specific synthetic markers before copying
the original bytes. Run it against the preserved private captures:

```sh
PYTHONPATH=. .venv/bin/python \
  validation/linux_x64_repeat/ground_truth/prepare_public.py \
  --private-root /PRIVATE/repeats
```

The two Codex wire journals are **not** included: their exact bytes contain
runtime session/turn/window identifiers. All 11 original RAM images remain
private because whole-guest memory can contain ephemeral keys and unrelated
runtime state. These public logs permit an independent audit of the synthetic
truth and its digests, but **do not** make the 11 image-level scores publicly
recomputable without the original RAM images and the private Codex journals.
