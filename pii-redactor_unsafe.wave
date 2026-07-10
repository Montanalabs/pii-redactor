#! VULNERABLE pii-redactor — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant redact

let raw = fetch<web>
privileged { redact(raw) }  # tainted -> tool: REJECTED
