# osquery pack: lab-persistence-and-tooling

Scheduled every hour on `windows-endpoint`, differential results (only added/removed rows after the first run). Results: `logs-osquery_manager.result-*`.

Sources: [palantir/osquery-configuration](https://github.com/palantir/osquery-configuration) (last commit 2020-03-26, `89c2ae5`), adapted; osquery `windows-attacks` pack; lab additions.

| Query | Detects | Source |
|---|---|---|
| `startup_items` | T1547.001 Registry Run keys / Startup folder | osquery table |
| `runonceex_registry` | T1547.001 | Palantir windows-registry-monitoring (runonceex_persistence_registry) |
| `winlogon_helpers` | T1547.004 Winlogon Helper DLL | lab |
| `ifeo_debugger` | T1546.012 Image File Execution Options Injection | lab |
| `services` | T1543.003 Windows Service | lab (differential: only changes are reported) |
| `scheduled_tasks` | T1053.005 Scheduled Task | lab (differential) |
| `wmi_cli_consumers` | T1546.003 WMI Event Subscription | osquery windows-attacks style |
| `wmi_script_consumers` | T1546.003 WMI Event Subscription | osquery windows-attacks style |
| `dns_server_plugin_dll` | DnsAdmins privilege escalation on a DC (ServerLevelPluginDll) | Palantir windows-registry-monitoring (dns_plugin_dll_registry_exists) |
| `amsi_disabled` | Defense impairment (AMSI disabled) | Palantir windows-registry-monitoring (amsi_disabled_registry) |
| `telemetry_settings` | Defense impairment (logging disabled): a change or a removed row means tampering | Palantir windows-registry-monitoring (command_line_auditing_*, powershell_*_logging_*) |
| `security_tooling_services` | Defense impairment (security tool stopped) | Palantir security-tooling-checks (adapted to this lab's tools) |
| `yara_user_writable` | Malware / tool files on disk (YARA Forge Core) | lab |
