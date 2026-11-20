# Glossary Map

## Contexts

- [BYOC (Bring Your Own Cloud)](./libs/cua/crates/cua-byoc/GLOSSARY.md): running Cua sandboxes and Spaces in user-owned cloud accounts and connecting them back to a relay

## Relationships

- **BYOC → Sandbox Core (`libs/cua/crates/cua-sandbox-core`)**: registers cloud `Provider Location`s (`aliyun-ecs`, `aws`, etc.) and maps `Sandbox Image`s onto cloud instances
- **BYOC → Spaces Daemon (`libs/cua-spacesd`)**: bootstraps each cloud machine to run `cua-spacesd` and dial out to an account-mode or static-mode relay
