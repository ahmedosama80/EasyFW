# Third-party notices

EasyFW itself is under the [PolyForm Noncommercial License 1.0.0](LICENSE). It includes the following, under their own terms.

## IP to Country Lite, by DB-IP

- File: `src/EasyFW/Data/dbip-country-lite.csv.gz`, shipped beside `EasyFW.exe` as `dbip-country-lite.csv.gz`. Release of November 2026.
- [IP Geolocation by DB-IP](https://db-ip.com)
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). The file is unchanged.

## famfamfam flag icons

- File: `src/EasyFW/Data/flags.png`, built into `EasyFW.exe`. It's the sprite from [legacy-icons/famfamfam-flags](https://github.com/legacy-icons/famfamfam-flags) 1.0.0. The flag positions in `src/EasyFW/UI/Flags.cs` come from that package's stylesheet.
- The flag icons are by Mark James ([famfamfam.com](http://www.famfamfam.com/lab/icons/flags/)) and are public domain.
- The Guernsey (`gg`) icon is by Damien Guard, from his Silk companion set, under [Creative Commons Attribution 2.5](https://creativecommons.org/licenses/by/2.5/).
- The rest of the legacy-icons/famfamfam-flags package is under the MIT License. See its [LICENSE.md](https://github.com/legacy-icons/famfamfam-flags/blob/master/LICENSE.md).

## World map

The coastlines and country positions in `src/EasyFW/Core/WorldGeo.cs` were drawn for EasyFW and are part of it, under its own license.

## Blocklists (not included)

EasyFW doesn't ship any blocklist. When you tick one in **Options > Blocklists of bad addresses**, EasyFW downloads it from its publisher onto your PC, and its use is under the publisher's own terms:

- **Spamhaus DROP**, by The Spamhaus Project: [spamhaus.org/drop](https://www.spamhaus.org/drop/). Free to use under Spamhaus's terms for the DROP lists.
- **FireHOL Level 1**, by the FireHOL project, combined from several sources: [iplists.firehol.org](https://iplists.firehol.org/?ipset=firehol_level1). Each source list keeps its own terms.
- **Feodo Tracker**, by abuse.ch: [feodotracker.abuse.ch](https://feodotracker.abuse.ch/blocklist/). Published under CC0.
- **Emerging Threats compromised hosts**, by Proofpoint Emerging Threats: [rules.emergingthreats.net](https://rules.emergingthreats.net/blockrules/). Free under Emerging Threats' terms for the open rule sets.

## Online services

EasyFW can ask [ipify](https://www.ipify.org/) (with `checkip.amazonaws.com` and `icanhazip.com` as backups) for this PC's public IP, and GitHub for new releases. Both can be turned off in **Options**.
