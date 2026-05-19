---
description: Run make coverage and report the per-package breakdown
---

!`make coverage 2>&1`

From the output above:

- Reproduce the per-package `go tool cover -func` totals (one line per package, plus the merged total).
- State whether the merged total cleared the threshold reported in the
  `Merged coverage: …%` line.
- Flag any package noticeably below the project's overall coverage so the
  user knows where adding tests would move the needle most.

Keep it tight — a table or short list, not prose.
