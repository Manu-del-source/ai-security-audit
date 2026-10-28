---
name: security-ai-llm
description: Review AI/LLM applications for prompt injection, unsafe tool execution, retrieval and tenant-isolation failures, sensitive-data leakage, unsafe output handling, and model-cost abuse. Use when a repository integrates models, agents, RAG, embeddings, or AI APIs.
---

# AI and LLM Security Audit

Audit the application around the model, not just the prompt text. Trace how untrusted content influences tools, data access, and downstream actions.

## Workflow

1. Identify model providers, system/developer prompts, user prompt construction, retrieval pipelines, vector stores, agent loops, tool/function definitions, output consumers, logging, and fallback paths.
2. Map trust boundaries between users, retrieved documents, external content, the model, tools, application services, and tenant data.
3. Test by static reasoning and safe local fixtures whether untrusted content can override instructions, invoke unauthorized tools, cross tenant boundaries, expose secrets or personal data, or cause unsafe downstream actions.
4. Inspect tool authorization at execution time. A prompt saying “do not do this” is not a security control; enforce identity, scope, argument validation, and least privilege in code.
5. Review retrieval filtering, document provenance, embedding/vector access controls, output validation, HTML/SQL/shell sinks, secret-bearing logs, data retention, and resource/cost limits.
6. Distinguish model uncertainty from code-level vulnerabilities. Demonstrate the actual path from attacker-controlled content to a sensitive operation.
7. Create candidates with exact code evidence and impact, then use a separate validation pass to try to disprove each candidate. Never report a hypothetical model response as a confirmed exploit without a reproducible path.
8. Redact secrets and private data. Use only synthetic fixtures for prompt-injection or data-exfiltration demonstrations.

## References

- Core workflow: `../../SKILL.md`
- AI playbook: `../../agents/ai-llm-security.md`
- Injection playbook: `../../agents/injection.md`
- AI rules: `../../rules/ai.md`
- Validator protocol: `../../validation/finding-validator.md`
