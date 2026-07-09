#! PII redactor — untrusted a document can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires redact — the pii redactor sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant redact

type FieldKind = Email | Phone | Ssn
type Decision = Redact(FieldKind) | Pass

let raw = fetch<web>  # UNTRUSTED a document — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { redact(d) }  # act on the trusted decision only
