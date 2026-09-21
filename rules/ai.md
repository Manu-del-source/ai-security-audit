# Rules: AI / LLM Applications

Load when `summary.hasAI` is true. Complements `agents/ai-llm-security.md`.

## Prompt boundaries

- Locate every place user text enters a prompt. Delimiters/structural
  separation present? Instruction-vs-data separation is a spectrum; note the
  mechanism (roles API, XML tags, nothing).
- System prompts in code vs fetched at runtime; secrets or internal rules
  inside system prompts (leakage impact amplifier).

## Tool calling

- Inventory tools: name, capability (read/write/execute/network), argument
  schema, authorization re-check per invocation.
- The dispatch loop: does it validate arguments against the schema *before*
  execution, or trust the model's JSON? Who is the principal for tool
  actions — the invoking user or a service account (over-privileged
  service principal = escalated agency)?
- Side-effectful tools without confirmation gates: finding.

## RAG / retrieval

- Ingestion: who can write documents that get retrieved (poisoning surface)?
- Query: ownership/tenant filters applied at retrieval? Vector IDs from
  client trusted? Metadata filters enforced server-side?
- Chunk authorization: retrieved chunks re-checked against the requesting
  user's permissions, or returned wholesale?

## Model output handling

- Output parsed as JSON then used in queries/commands/redirects: validation
  gap = injection via model (the model is a confused deputy).
- Output rendered: XSS via model output (markdown rendering with raw HTML);
  exfiltration via markdown images/links hitting attacker URLs.
- Output used for authorization decisions ("is this user an admin? yes" from
  a model call): never acceptable.

## Agent loops

- Stop conditions, step/spend budgets, human-confirmation gates on
  destructive tools.
- Memory/session state scoping: cross-user memory leakage.

## Cost & abuse

- Token limits per request/response; per-user quotas; unauthenticated
  endpoints invoking paid models (resource-exhaustion crossover — file once,
  here or there, not both).

## Typical AI findings

| Pattern | Risk |
|---|---|
| `prompt = f"{system}\nUser: {user_input}"` then tools run | direct prompt injection → tool abuse |
| Vector search `where: {}` (no user filter) | cross-user context leakage |
| `JSON.parse(model_output)` → `db.query(sql built from it)` | injection via model |
| Agent with `send_email` tool, no confirm step | excessive agency |
| Chat rendering `marked(output)` without sanitizer | XSS via model output |
