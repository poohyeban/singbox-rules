# Data attribution and scope

The root MIT license covers the independently implemented generator and tests.
It does not replace the licenses or terms of upstream datasets.

- **v2fly/domain-list-community**: domain data under its upstream MIT license,
  reproduced in `licenses/v2fly-MIT.txt`. Domain outputs retain original rule
  meanings; source annotations are removed after upstream category selection.
  Source: https://github.com/v2fly/domain-list-community
- **AdGuard DNS Filter**: source and derived AdGuard rules remain under GNU
  GPL version 3; see `licenses/AdGuard-GPL-3.0.txt`. This project modifies the
  source into a conservative hostname-only routing blocklist. The downloaded
  source, readable derived rules, omission report, and conversion code are all
  included. `dist/geosite.dat` contains this AdGuard-derived component.
  Source: https://github.com/AdguardTeam/AdGuardSDNSFilter
- **GeoLite2 Country and ASN**: this product includes GeoLite2 data created by
  MaxMind, available from https://www.maxmind.com. Database and contents
  copyright MaxMind, Inc. Data is distributed by P3TERX/GeoLite.mmdb with the
  GeoLite2 EULA and CC BY-SA 4.0 notices. Country/ASN selections and their CIDR
  aggregation are modifications; derived IP lists and their DAT representation
  retain applicable upstream terms. See `licenses/GeoLite-CC-BY-SA-4.0.txt`,
  https://www.maxmind.com/en/geolite2/eula and
  https://github.com/P3TERX/GeoLite.mmdb.
- **OpenAI public network data**: official Voice prefixes and a manually
  reviewed Help Center domain snapshot are used as routing inputs. Source URLs
  are recorded in the snapshot and manifest. These are not an enterprise
  firewall allowlist or an exhaustive list of infrastructure owned by OpenAI.

Source-file SHA-256 values and generated artifact hashes are recorded in
`dist/manifest.json`. The DAT encoder follows the public Xray geodata schema:
https://github.com/XTLS/Xray-core/blob/v26.9.9/common/geodata/geodat.proto

No router configuration, node credentials, traffic records, personal identity,
or workstation metadata is an input to the published rules.

- **Sukka and contributors / SukkaW/Surge**: the reviewed Meta service
  supplements derive from `Source/non_ip/global.conf` under AGPL-3.0. See
  `licenses/Sukka-AGPL-3.0.txt` and https://github.com/SukkaW/Surge.
  Initial modifications: 2026-10-03; service selection, Xray conversion and
  suffix compaction. The combined WhatsApp, Instagram and Facebook datasets
  and their DAT components are distributed under AGPL-3.0. Separately stored
  v2fly-only subsets retain MIT. Corresponding transformation code, review
  mapping, readable subsets and source hashes are included in this repository.
