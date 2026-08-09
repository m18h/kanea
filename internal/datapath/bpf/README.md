# License note

The BPF C sources in this directory (`kanea.c`, `headers.h`) are
dual-licensed **GPL-2.0-only OR MIT** (`SPDX-License-Identifier:
(GPL-2.0-only OR MIT)`), and the programs declare `"Dual MIT/GPL"` in
their license section, because several kernel BPF helpers are exported
only to programs carrying a GPL-compatible license string. This applies
to these sources and the object files compiled from them only; the rest
of the repository remains Apache-2.0 (see the top-level `LICENSE`).
