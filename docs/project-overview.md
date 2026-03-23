# AmiWeb Project Overview

AmiWeb targets AmigaOS 3.2 and newer only.
Older AmigaOS versions are intentionally out of scope and should continue using classic AWeb.

The repository root contains the primary development tree.
A reference snapshot of the AWeb 3.6 upstream codebase is tracked separately under `vendor/amigazen-aweb3/`.

## Project direction

- native AmigaOS 3.2+ APIs only
- plain C89 in core code
- compiler-agnostic source where practical
- small, reviewable maintenance steps
- reproducible build and test discipline

## About this fork

AmiWeb is an HTML 3 /4 era web browser for Amiga. This fork focuses on maintaining and improving the codebase as a native  Amiga application for AmigaOS 3.2, with emphasis on buildability, system integration, and long-term maintainability.

The authors of AWeb are not affiliated with this fork. Redistribution remains subject to the terms described in the project documentation, especially `LICENSE` and `/docs/LICENSE.md`.

## Repository layout

- repository root: active fork development
- `vendor/amigazen-aweb3/`: imported upstream reference snapshot

## About AmiWeb

AmiWeb base one of the most sophisticated web browsers of its era on the Amiga platform, AWeb 3. The original author, Yvon Rozijn, released AWeb as open source under the AWeb Public License.

This fork continues development on a classic Amiga baseline with a focus on native APIs, maintainable source code, and a reproducible development workflow.
