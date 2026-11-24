# Glossary Map

## Contexts

- [BYOC (Bring Your Own Cloud)](./libs/cua/crates/cua-byoc/GLOSSARY.md): running Cua sandboxes and Spaces in user-owned cloud accounts and connecting them back to a relay
- [Spaces](./libs/cua/crates/cua-spaces/GLOSSARY.md): registering, connecting, listing, and sharing local, direct, cloud, and relayed Spaces

## Relationships

- **BYOC → Sandbox Core (`libs/cua/crates/cua-sandbox-core`)**: registers cloud `Provider Location`s (`aliyun-ecs`, `aws`, etc.) and maps `Sandbox Image`s onto cloud instances
- **BYOC → Spaces Daemon (`libs/cua-spacesd`)**: bootstraps each cloud machine to run `cua-spacesd` and dial out to an account-mode or static-mode relay
- **Spaces → Sandbox Core (`libs/cua/crates/cua-sandbox-core`)**: resolves qualified Space references and delegates sandbox lifecycle operations
- **BYOC → Spaces (`libs/cua/crates/cua-spaces`)**: registers provisioned cloud sandboxes as `Space`s reached via `Account Relay Mode` or `Static Relay Mode`
