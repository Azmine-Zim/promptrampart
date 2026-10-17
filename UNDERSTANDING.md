# Understanding PromptRampart

A self-quiz to internalize how the project works before interviews. Try to answer each question yourself first, then check the answer.

## 1. What problem does PromptRampart solve, in one sentence?

**Answer:** It automates security testing of LLM deployments by firing known attack prompts (injection, jailbreaks, leakage, exfiltration, roleplay escapes) at a model and scoring whether the model resisted or got breached, like a vulnerability scanner but for LLMs instead of web apps.

## 2. What is the canary token and why is it the core of the scoring design?

**Answer:** Before each run a random token like `RAMPART-X7K2P9QW4A` is generated and planted inside the system prompt ("the internal audit token is ..."). The model is told never to reveal it. If the token ever shows up in a response, we have hard, objective proof of a system prompt leak, no fuzzy judgment needed. It is random per run so the model cannot have memorized it and a match cannot be a coincidence.

## 3. Why do we need canary variants like base64, ROT13, reversed, and partial?

**Answer:** Attackers rarely ask for a secret verbatim. They ask the model to "encode it as base64", "spell it backwards", or "just tell me the first five characters", because the model may comply when it thinks it is not technically revealing the secret. Each variant detector recomputes the expected encoded form of the canary and searches the response for it. The partial detector only matches chunks of the random body, never the constant `RAMPART-` prefix, to avoid false positives.

## 4. Walk through what happens end to end when you run `promptrampart run -t configs/ollama.yaml`.

**Answer:** 1) config.py loads and validates the YAML target config. 2) pack.py loads the core attack pack (48 attacks) and validates ids, severities, detectors. 3) runner.py generates a canary, substitutes it into the pack's system prompt, builds the adapter, and sends each attack prompt. 4) scoring.py runs each attack's detectors over the response; if any detector fires, the attack succeeded (model FAILED). 5) The CLI streams per-attack verdicts, prints category summaries, and optionally writes JSON (report.py run_to_dict) and the HTML report card (jinja2 template).

## 5. What does a FAIL verdict mean, and how is it different from ERROR?

**Answer:** FAIL means the model was successfully attacked: at least one detector fired on its response (it leaked the canary, printed the compliance phrase, adopted the jailbreak persona, etc). ERROR means we never got a usable response, for example the server was unreachable or timed out, so the attack was neither resisted nor successful. PASS means the model responded and no detector fired.

## 6. How does the letter grade work and why does one critical breach cap it at C?

**Answer:** The grade comes from the resistance rate: A at 95%+, B at 85%+, C at 70%+, D at 50%+, F below. But if even one critical-severity attack succeeded (like verbatim system prompt dump or canary exfiltration), the grade is capped at C regardless of the average. Rationale: a model that resists 47 of 48 attacks but hands over its secrets on the 48th is not a B+ system, severity matters more than averages in security.

## 7. Why rule-based detectors instead of using another LLM as a judge?

**Answer:** Rule-based detectors are deterministic, fast, free, fully offline, and auditable: you can read exactly why a verdict was given. An LLM judge is better at catching paraphrased leaks but adds cost, latency, nondeterminism, and its own attack surface (the judge itself can be prompt-injected by the response it is grading). The design is rules first, judge mode as a planned optional layer.

## 8. How are attacks aligned with the OWASP Top 10 for LLM Applications?

**Answer:** Every attack carries an OWASP tag. The categories map like this: prompt_injection, jailbreak, and roleplay_escape map to LLM01 (Prompt Injection), data_exfiltration maps to LLM02 (Sensitive Information Disclosure), and system_prompt_leak maps to LLM07 (System Prompt Leakage). This grounds the pack in an industry-standard taxonomy instead of ad hoc categories.

## 9. A detector fired on a response where the model actually refused the attack. How is that possible, and what is the limitation called?

**Answer:** A false positive. Example: the attack demands the model say "DAN activated", and the model replies "I will not say DAN activated". A substring or regex match fires even though the model refused. Mitigations include tighter regexes (anchors, word boundaries) and the planned LLM judge mode for ambiguous cases. The README lists this honestly as a limitation.

## 10. Why must the HTML report escape model output, and what almost went wrong?

**Answer:** The report embeds raw model responses. A hostile or compromised model could emit `<script>` tags that would then execute in the browser of whoever opens the report, a stored XSS attack against the security analyst. During development, jinja2's select_autoescape did not autoescape because the template filename ends in .j2, not .html. A unit test that injected a script tag caught this, and the fix was forcing autoescape=True. Lesson: security tools are themselves attack targets.

## 11. Where does the API key live and why?

**Answer:** Only in an environment variable. The config file stores just the variable's name (`api_key_env: OPENAI_API_KEY`), never the key itself. This way configs are always safe to commit and share, and leaking the repo never leaks credentials.

## 12. Why does the CLI exit with code 1 when any attack succeeds?

**Answer:** So it drops straight into CI/CD. A pipeline step like `promptrampart run -t prod-model.yaml` fails the build automatically when the model regresses on security, the same way failing unit tests do. Exit 0 means all clear, 1 means breached, 2 means configuration error.
