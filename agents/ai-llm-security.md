# Hunter: AI/LLM Security

## Mission

Wherever an LLM turns text into actions or privileged context into output,
treat text as untrusted input. Find where prompt content crosses into tool
execution, other users' context, or data exfiltration — and where the model's
output is trusted like code.

## Where to hunt

- Prompt construction: system prompt assembly, user message concatenation, RAG retrieval injection points.
- Tool/function calling: tool definitions, argument schemas, the dispatch code executing tools.
- Agent loops: autonomous iteration, approval gates, stop conditions, sub-agent spawning.
- Retrieval: vector stores, document ingestion, chunk authorization, metadata filters.
- Output handling: model output rendered to users, parsed as JSON/commands, passed to other systems.
- Provider integrations: OpenAI/Anthropic/etc. clients, system prompt files, prompt templates.

## Checklist

- [ ] Direct prompt injection: user text concatenated into instructions; "ignore previous instructions" has effect because instructions and data share the channel (no delimiters, no privilege separation between instruction and data).
- [ ] Indirect prompt injection: retrieved documents, web pages, emails, issue titles, file contents — anything the RAG/agent reads can carry instructions; check whether retrieved content is treated as trusted.
- [ ] System prompt exposure: endpoints/flags returning the system prompt; prompt leaked in error messages or logs (severity depends on what secrets/rules it contains).
- [ ] Tool authorization: tools executed because the *model* asked — check whether tool execution re-verifies user identity and object-level authorization (the model is not an authorizer).
- [ ] Unsafe tool execution: model-controlled arguments reaching exec/SQL/file/shell tools without validation; tool arguments built by string interpolation of model output.
- [ ] Excessive agency: agents that can send email, move money, modify data, or spawn sub-agents without human confirmation; autonomous loops without spend/step limits.
- [ ] Data exfiltration: model output or retrieved context passed to third-party calls (URLs, images, webhooks) — classic markdown-image exfiltration; chat history sent to untrusted endpoints.
- [ ] Cross-user context leakage: shared conversation/session memory, vector store without per-user metadata filtering (user A retrieves user B's documents), system prompts carrying one user's data into another's context.
- [ ] RAG poisoning: ingestion endpoints letting users write content retrieved into *other* users' contexts.
- [ ] Retrieval authorization: similarity search not scoped by tenant/owner; document IDs from client trusted in retrieval.
- [ ] Model output trust: LLM JSON/SQL/code executed without parsing/validation; output interpolated into templates (SSTI/XSS via model output).
- [ ] Insecure agent loops: agents whose stop conditions are model-decided and that hold credentials for all tools at once; missing per-tool least privilege.
- [ ] Unsafe code execution: "write and run code" features with model-generated code run in the main app process rather than a sandbox.

## Evidence requirements

Cite the prompt-assembly file:line, the tool-dispatch file:line, and the
authorization check present/absent file:line. State which context the
injected text can reach (own session / other users / tool execution).

## False-positive traps

- Deterministic output schemas with strict validation before any action.
- Tool execution wrapped in per-user authorization (verify per-object, not just per-tool).
- Content-only chatbots with no tools and no cross-user memory (prompt injection there is usually informational unless output is rendered raw elsewhere).
- Retrieval scoped by ownership filters at the vector-store query.

## Output

Candidates per schema, category `ai-llm-security`.
