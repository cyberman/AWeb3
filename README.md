# AmiWeb

AmiWeb is an independent continuation of the AWeb codebase for classic Amiga systems.

## Platform policy

AmiWeb targets **AmigaOS 3.2 and newer only**.  
Older AmigaOS versions are intentionally out of scope and should continue using classic AWeb.

## Project goals

- native AmigaOS 3.2+ system integration
- plain C89 in core code
- compiler-agnostic source where practical
- small, reviewable maintenance steps
- reproducible build and test discipline

## Repository role

This repository is the active AmiWeb development tree.

`vendor/amigazen-aweb3/` contains a separately tracked upstream reference snapshot for comparison and review only. It is not part of the AmiWeb product tree and is not used as an implicit source of truth.

## Background

AmiWeb continues the AWeb lineage as a native Amiga application with an explicit AmigaOS 3.2+ baseline and a focus on maintainability, buildability, and long-term clarity.

The original AWeb authors are not affiliated with this repository. Redistribution remains subject to the project license and accompanying documentation.

## Documentation

Detailed documentation has been split into separate files:

- `docs/project-overview.md`
- `docs/html-support.md`
- `docs/javascript-support.md`
- `docs/acknowledgements.md`

## Current focus

Current work is centered on:

- establishing a clean hosted C89 build path
- reducing warning noise in legacy modules
- clarifying product structure and packaging
- preparing a hard AmigaOS 3.2+ product baseline

## Status

AmiWeb is under active restructuring and maintenance.
