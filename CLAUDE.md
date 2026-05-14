# CLAUDE.md

## Project Mission

This repository contains `cpts-lab-tools`: a local-first tooling project designed to
complement my CPTS / HTB field manual.

The goal is to turn the workflows, commands, checklists, and methodology from my
field manual into practical helper tools that improve:
- lab workflow speed
- note-taking consistency
- command generation
- evidence capture
- report preparation
- methodology discipline
- authorized lab reproducibility

This is not an exploit development repo and not a real-world attack automation
platform.

## Reference Material

Use the following directory as read-only reference material:

`/Users/enriquefolte/Code/Blog/field-manual-blog/site`

That directory contains the published/static version of my field manual blog.

Extract:
- recurring command patterns
- workflow structure
- methodology checklists
- service-specific enumeration logic
- troubleshooting logic
- reporting language
- placeholders and naming conventions
- CPTS/HTB lab-oriented usage patterns

Do not blindly copy large chunks verbatim from the blog. Convert the methodology into
useful local tooling.

## Working Directory Rules

Primary working repo:

`/Users/enriquefolte/Code/cpts-lab-tools`

Only modify files inside this repository unless explicitly instructed otherwise.

Treat the blog/site directory as read-only.

Before making large changes:
1. inspect repo structure
2. inspect existing README/docs/scripts
3. propose a short implementation plan
4. then edit incrementally

## Product Direction

Build a tool that “wonderfully complements” the field manual.

Useful feature ideas:
- command/template generator for common CPTS workflows
- service-based checklist generator
- evidence folder scaffolding
- markdown note generator using my field manual style
- target workspace initializer
- reporting snippets generator
- tool-output parser/summarizer
- methodology reminder engine
- “what next?” helper based on open ports/services
- lab-safe command builder using placeholders

Prefer small, composable CLI features over a huge fragile application.

## Safety / Scope Rules

Assume all usage is for authorized labs, HTB, CPTS preparation, or client-approved
work.

Do not add features designed for:
- stealth against real organizations
- credential theft outside lab context
- persistence
- evasion
- malware deployment
- phishing
- destructive actions
- automated exploitation against public IPs

It is acceptable to create:
- enumeration helpers
- checklist generators
- report templates
- lab command builders
- local parsers
- evidence organizers
- defensive/reporting explanations

## Style Requirements

The tool should reflect my field manual style:
- tactical
- concise
- checklist-driven
- command-heavy
- placeholder-ready
- lab-safe
- report-oriented

Use placeholders consistently:
- `[TARGET_IP]`
- `[TARGET_HOST]`
- `[DOMAIN]`
- `[USER]`
- `[PASS]`
- `[HASH]`
- `[LHOST]`
- `[LPORT]`
- `[OUTPUT_DIR]`

Prefer clear terminal UX.

Every generated workflow should include:
- assumptions/scope
- prerequisites
- what to run next
- expected output
- verification steps
- common failure points and fixes
- short report note

## Engineering Preferences

Prefer Python unless there is a strong reason not to.

Use a clean CLI structure.

Keep dependencies minimal.

Avoid hardcoding private paths unless they are configurable.

Add tests for core logic when practical.

Avoid overwriting user files without confirmation or a `--force` flag.

Generated output should be Markdown-friendly and Obsidian-friendly.

## Repository Hygiene

Do not commit secrets, credentials, lab flags, VPN configs, private IP notes, or
proprietary HTB content.

Do not vendor large generated site content into this repo.

If reading from the blog/site directory, treat it as external reference material.

Before finalizing changes, run:
- `git status`
- relevant tests
- basic CLI smoke tests
