# Conversion contract and verification limits

The reference builder is vendored without source changes. Its source URLs, recursive category resolution, annotation handling, reviewed OpenAI exclusions, Meta service selection, AdGuard projection, ASN selection, address-family handling, CIDR collapse, minimum counts, and shrink checks run before conversion. Reference hashes cover the complete vendored inventory; the remote drift check additionally detects newly added or deleted inputs and modules. The remote reference repository is read only.

The input to the adapter is the reference's resolved domain/IP files. Exact names map to `domain`, label-bounded suffixes to `domain_suffix`, substring rules to `domain_keyword`, and unchanged Go expressions to `domain_regex`. Destination CIDRs map to `ip_cidr`. These alternatives share a single default headless rule with the documented OR semantics. Conversion never guesses an unsupported directive, changes a prefix length, substitutes an apex-inclusive suffix for a subdomain-only wildcard, or suppresses an unknown rule.

The current official documentation describes source versions 1–5. Version 2 is sufficient for the fields used here and supports the optimized suffix representation; versions 3–5 add fields that these datasets do not use. The compiler command is the documented `sing-box rule-set compile --output FILE.srs FILE.json`. The binary writer is always the official compiler, not a custom SRS implementation. Compilation and `sing-box check` are both required: storing a regex string alone is insufficient proof that the routing engine accepts it.

The complete JSON inventory is checked against every resolved reference entry. The complete resolved-source inventory is also checked, so changing both the JSON and its readable input cannot hide an omission. Every published binary must exactly reproduce the official compiler's complete output, not merely have a plausible header or matching sidecar hash. The manifest records source bytes and all published outputs, excluding its own self-referential hash.

Engine routing uses the unmodified reference Xray verifier plus additional deterministic samples and isolated regex cases. Every source regex has reviewed positive/negative targets in `tests/regex_witnesses.json`; it runs by itself in both engines, preventing a broad suffix rule from hiding a regex mismatch. Exact-vs-suffix boundaries, apex-excluding wildcards, substring matching, IPv4/IPv6 edges, all seven categories and Google-before-China priority are covered. sing-box routes targets only to local SOCKS capture servers, so neither domain resolution nor external target connections are necessary. Xray uses local blackhole outbounds. Source JSON and the published SRS run through the same native cases on every tested sing-box version.

Finite runtime cases do not establish every property of arbitrary future regex languages. The assurance for unchanged current expressions combines verbatim projection, the engines' Go regexp implementations, complete native loading, and isolated regression witnesses. A new expression lacking a reviewed witness blocks publication rather than silently receiving partial coverage. Routing-engine normalization outside the rule set, application sniffing, router DNS choices, and user-selected actions remain configuration responsibilities. Tests include case folding for exact names and the observed trailing-dot boundary; the converter does not add new regex flags or normalize runtime traffic.

Existing AdGuard omissions/under-blocking are inherited reference decisions, not new conversion losses. Unknown upstream exceptions remain fatal under the original builder. Conditional AdGuard features are not expanded using sing-box's separate AdGuard converter, because doing so would change the reference's matching scope. Missing ASN records or an absent IPv6 source selection are reported without synthesizing address ranges.

Official sources consulted on 2026-10-11:

- [Latest stable release, 1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)
- [Source format](https://sing-box.sagernet.org/configuration/rule-set/source-format/)
- [Headless rule fields and OR semantics](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)
- [Local and remote rule sets](https://sing-box.sagernet.org/configuration/rule-set/)
- [Official compiler implementation at v1.14.3](https://github.com/SagerNet/sing-box/blob/v1.14.3/cmd/sing-box/cmd_rule_set_compile.go)
- [Original domain model and reviewed wildcard handling](https://github.com/poohyeban/passwall2-rules/blob/e8448d37274cb2141405e224aac8161c28fbee95/scripts/model.py)
