# Vault AWS CLI/SDK Credentials Helper

The Vault AWS CLI/SDK Credential Helper (`vacc`) implements the AWS CLI/SDK external credentials helper interface as outlined here: https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-sourcing-external.html

The tool allow for using short-lived credentials issued through Vault / OpenBao to be used by scripts and programs which might run longer than the credentials are valid for.

## Installation

<!-- TBD -->

## Configuration

Typical configuration is via CLI flags, but the tool also supports loading some or all of the config from a config file.

|         Flag          |           Env            | Description                                         |
| :-------------------: | :----------------------: | --------------------------------------------------- |
|    `-c` `--config`    |      `VACC_CONFIG`       | Configuration file path                             |
|  `-V` `--vault-addr`  |       `VAULT_ADDR`       | Vault server URL                                    |
| `-C` `--vault-cacert` |      `VAULT_CACERT`      | (optional) Vault CA certificate file                |
|   `--vault-capath`    |            ??            | (optional) Vault CA certificates directory          |
|    `-m` `--mount`     |       `VACC_MOUNT`       | Vault path for `aws` secrets backend, default `aws` |
|     `-r` `--role`     |       `VACC_ROLE`        | Vault role                                          |
|     `-t` `--ttl`      |        `VACC_TTL`        | Credential TTL                                      |
|     `-T` `--type`     |  `VACC_CREDENTIAL_TYPE`  | Credential Type (`sts` or `creds`)                  |
|       `--cache`       | `VACC_CACHE_CREDENTIALS` | Cache credentials in keyring or secure storage      |
