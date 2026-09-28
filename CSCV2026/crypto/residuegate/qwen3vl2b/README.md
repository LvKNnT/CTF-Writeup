# Local Qwen model files

This directory contains model metadata and tokenizer files used by
[`../sol.py`](../sol.py) for local embedding generation. The files come from
`Qwen/Qwen3-VL-2B-Instruct` at revision
`89644892e4d85e24eaac8bacfd4f463576704203`.

The approximately 4.26 GB `model.safetensors` weights are excluded by the
repository's `.gitignore`. They are required locally and are not included in a
fresh clone. Use the weights from the same pinned revision; the solver loads
the model from local files only.
