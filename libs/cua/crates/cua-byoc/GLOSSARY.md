# Cua BYOC (Bring Your Own Cloud)

Running Cua sandboxes and Spaces inside a user's own cloud account and connecting each machine back to a relay over outbound tunnels without requiring inbound ports.

## Language

**Provider Location**:
The canonical identifier for a cloud or sandbox platform target (such as `aliyun-ecs`) used to route sandbox creation and reference sandboxes without colliding across distinct products of the same cloud vendor.
_Avoid_: cloud name, `provider:subservice`

**Cloud Image ID**:
A cloud provider's operating-system image identifier (such as an Alibaba Cloud ECS `m-xxx` custom image or official OS image) used to boot a cloud VM.
_Avoid_: sandbox image, container image

**Sandbox Image**:
A Cua workload family or container image reference (such as `linux`, `linux-slim`, or `windows`) describing the target environment rather than the cloud vendor's VM template.
_Avoid_: ECS image ID, VM template

**Direct VM Sandbox**:
A single-sandbox cloud VM (Windows 10/11/Server or Linux) that runs `cua-spacesd` directly on the guest OS and joins a relay without an intervening container or nested hypervisor.
_Avoid_: bare-metal sandbox, nested VM, host mode

**Docker-on-VM Sandbox**:
A single-sandbox Linux cloud VM whose guest OS runs only Docker to host one containerized sandbox carrying `cua-spacesd`.
_Avoid_: direct VM sandbox, native sandbox

**Pool Host**:
A shared cloud machine that joins an account's elastic pool to host multiple sandboxes concurrently, rather than serving a single sandbox.
_Avoid_: sandbox VM, direct VM sandbox

**Account Relay Mode**:
A relay connection backed by user account authentication and a machine directory, where each cloud sandbox is registered dynamically under the signed-in account.
_Avoid_: hosted-only relay

**Static Relay Mode**:
A self-hosted relay connection authenticated by a shared registration token and per-sandbox environment tokens, requiring no account sign-in or identity provider.
_Avoid_: unauthenticated relay, tokenless relay

**Spacesd Mirror URL**:
The connection-level location from which Linux and Windows Direct VM Sandboxes download `cua-spacesd` when it is not pre-installed in the image, given as either a directory prefix ending in `/` or a single-file URL, with optional `{version}` and `{arch}` placeholders.
_Avoid_: binary override, custom download link, artifact base URL
