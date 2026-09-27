# Bind-Mounts on Host and Guest

A single-context glossary for the homelab monorepo: the bind-mounts playbook, its planned conversion into a bind_mounts capability role under a profile playbook, and the smolvm vocabulary they share. Terms here are the project's own vocabulary; decisions that constrain implementation live in the rhizome project record, not here.

## Language

**Host**:
The machine that runs smolvm and the bind-mounts playbook; all managed machines are reached from it via `smolvm machine exec`/`cp`. The omp agent sessions for this repo run inside `arch-vm`, which is itself a guest, so the agent shell has no `smolvm` binary and cannot run the playbook's host-side tools.
_Avoid_: control machine, ansible controller

**Guest**:
A smolvm machine managed by this playbook. Never an Ansible inventory host; reached only through host-side `smolvm machine exec`/`cp`.
_Avoid_: VM, node, target host

**Lifecycle owner**:
The playbook/role entitled to create, start, and stop machines. Decided: the VM-provisioning parent; bind_mounts requires machine preconditions and refuses instead of changing machine state.
_Avoid_: machine manager

**Volume owner**:
The playbook/role entitled to attach, detach, and prove volumes for a machine. Decided: bind_mounts, under policy set by the parent's configuration; foreign volumes are refused or forced, never silently adopted.
_Avoid_: disk owner

**Bind mode**:
Configuration mode where a share directory on the host is bind-mounted into the guest at a configured target, with per-mount guest binds layered on top.
_Avoid_: shared mode

**Direct mode**:
Configuration mode with no share bind; each configured mount is attached as its own volume and mounted directly.
_Avoid_: standalone mode

**Provenance ledger**:
The run-written record (`~/.local/state/bind-mount-on-host-and-guest/`) naming the volumes, binds, and guest artifacts a run created; removals require it as proof unless forced.
_Avoid_: state file, inventory

**Stacked bind**:
A second bind mounted at a target that already carries one, used to layer per-machine content over the share bind; identity is proven by device:inode, not by path.
_Avoid_: overlay mount

**Scratch machine**:
A disposable guest (currently `scratch-vm`) reserved for destructive verification, so `arch-vm` - a live, managed guest - is not risked.
_Avoid_: test VM

**Machine registry**:
The single list of managed machines and their inputs, owned by the parent playbook's configuration; bind_mounts consumes it as role variables and never reads a config file of its own. Decided: a git-ignored standalone copy exists only until the parent playbook is verified, then it is retired.
_Avoid_: vars.yml, machine list, inventory

**Capability role**:
A small, single-purpose, reusable unit of automation, named for the function it performs (bind_mounts is one); it carries its own variables, files, and defaults, and is parameterized by the machine registry. Future setups like vim or emacs configuration would also be capability roles.
_Avoid_: server role, machine role, parent role

**Profile playbook**:
A thin, executable playbook that maps a machine to the capability roles it needs ("this machine is a dev server"). The former "parent playbook" of the conversion decisions; machine profiles live at the playbook level, never as monolithic server-type roles.
_Avoid_: parent playbook, site playbook
