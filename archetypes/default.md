+++
date = '{{ .Date }}'
draft = true
title = '{{ replace .File.ContentBaseName "-" " " | title }}'
description = ''
tags = []
+++

Briefly explain what you decided to investigate and why.

## What caught my attention

Document the first event, process, alert, artifact or behaviour that started the investigation.

## Following the trail

Walk through the investigation in the same order you actually worked it.

Focus on the pivots that moved the hunt forward:

- PID / PPID relationships
- parent and child processes
- command-line activity
- file paths
- network activity
- related artifacts
- additional hunts triggered by what you found

### Investigation pivot

Explain what you found and why it made you pivot.

```text
Example query, command line or telemetry
```

### Next pivot

Continue following the evidence rather than reorganising it by ATT&CK phase.

## What the activity tells us

Step back from the timeline and explain the attacker behaviour or interesting TTPs that became visible during the investigation.

## Hunting and detection ideas

Document reusable hunting queries, behavioural patterns, detection opportunities and telemetry gaps.

## Takeaways

Summarise what was useful, what was difficult to observe, and what you learned from the investigation.