# Attribution and modifications

The generator adapter, workflow and new tests use the root MIT license. The
reference implementation and its original notices are retained byte-for-byte
under `vendor/passwall2/`, from passwall2-rules commit
`e8448d37274cb2141405e224aac8161c28fbee95`.

Reference: https://github.com/poohyeban/passwall2-rules

Initial sing-box modifications: 2026-10-11. Resolved domain kinds and CIDRs are
mapped to sing-box JSON fields and compiled by official sing-box. The reference's
source selection and reviewed input data are unchanged. Native compatibility
tests, source/JSON/binary inventory checks, provenance reports and fail-closed
publication are added. Generated source subsets remain available in `rules/`.

- v2fly/domain-list-community: domain data under MIT; see
  `licenses/v2fly-MIT.txt` and https://github.com/v2fly/domain-list-community.
- AdGuard DNS Filter: source and derived AdGuard JSON/SRS remain under GPL-3.0;
  see `licenses/AdGuard-GPL-3.0.txt`. The original downloaded filter, modified
  readable rules, omission report and corresponding source code are included.
  https://github.com/AdguardTeam/AdGuardSDNSFilter
- GeoLite2 Country/ASN: this product includes GeoLite2 data created by MaxMind,
  available from https://www.maxmind.com. Country/ASN selections, CIDR lists
  and derived China/OpenAI JSON/SRS retain applicable GeoLite2 EULA and
  CC BY-SA 4.0 terms. See `licenses/GeoLite-CC-BY-SA-4.0.txt`,
  https://www.maxmind.com/en/geolite2/eula and
  https://github.com/P3TERX/GeoLite.mmdb.
- Sukka and contributors: reviewed Meta supplements derive from SukkaW/Surge
  under AGPL-3.0. Combined WhatsApp, Instagram and Facebook JSON/SRS retain
  AGPL-3.0; v2fly-only readable source subsets retain MIT. Corresponding
  transformation code, review mapping, readable subsets, selection diagnostics
  and source hashes are included. See `licenses/Sukka-AGPL-3.0.txt` and
  https://github.com/SukkaW/Surge.
- OpenAI public data: official Voice prefixes and the reference's reviewed Help
  Center domain snapshot are routing inputs, not an ownership inventory or an
  exhaustive enterprise firewall allowlist. Source URLs and reviewed-input hashes
  are retained in the manifests.

MIT does not replace dataset licenses. Original detailed attribution is also
available in `vendor/passwall2/NOTICE.md`. No private client traffic, router
configuration, proxy credentials or user identity is an input to rule generation.
