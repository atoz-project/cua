# Cua Spaces

Managing computers and the isolated or remote Spaces they provide across local runtimes, direct network addresses, and relays.

## Language

**Computer**:
A physical or virtual machine added to a user's account that can host child Spaces, share its own desktop, or both.
_Avoid_: node, worker

**Space**:
An addressable environment where a person or agent works: primarily an isolated container, VM, or microVM sandbox, or an existing machine added by address or shared desktop that exposes the same control capabilities.
_Avoid_: instance, target

**Shared Desktop**:
A Computer's own screen, input, shell, and files exposed as a Space while desktop sharing is enabled on that Computer, without sandbox isolation.
_Avoid_: sandbox Space

**Direct Host**:
A machine registered at a direct network address to provision and forward child Spaces without joining an account relay directory.
_Avoid_: relay computer

**Relay Attachment**:
Dynamic publication of an already-running Space onto an authenticated account's relay directory so other devices on that account can reach it.
_Avoid_: static relay join
