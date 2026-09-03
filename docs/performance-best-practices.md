# Performance Best Practices

How this collection actually behaves against CipherTrust Manager, and what you
can do about it.

> Earlier versions of this page described a resource-ID LRU cache, batched API
> calls and collected performance metrics. None of those existed in the
> collection. They are documented here as absent so nobody tunes settings that
> do nothing.

## What the collection does for you

**One authentication per session.** A JWT is cached in-process and shared by
every `CipherTrustClient` built during the same task, so a play does not
re-authenticate per module call. A `401` mid-play triggers one
re-authentication and a single retry.

**Transient failures on reads are retried.** A GET that fails with 429, 502,
503, 504 or a connection error is retried with backoff. Writes are never
replayed — a POST, PATCH or DELETE that may already have been applied fails
the task instead, because a duplicate write is worse than a failed one.

## What costs an extra request

**Idempotency costs one GET.** Every create and patch reads current state
before writing, so a task that changes nothing still makes one request. This
is what lets `changed` be accurate and `--check` work. It is not tunable, and
it is the right trade.

**A no-op patch still costs that GET.** If a play patches the same resource on
every run, the request happens even when the answer is "no change".

## What you can do

**Set connection parameters once.** `meta/runtime.yml` defines an `all` action
group, so `localNode` need not be repeated per task:

```yaml
- hosts: localhost
  module_defaults:
    group/thalesgroup.ciphertrust.all:
      localNode: "{{ cm_connection }}"
  tasks:
    - name: Create a group
      thalesgroup.ciphertrust.group_save:
        op_type: create
        name: analysts
```

This is about readability rather than speed, but it removes a class of
copy-paste mistake.

**Look up an id once, not per task.** Where several tasks act on the same
resource, resolve it with `cm_resource_get_id_from_name` and reuse the
registered value instead of letting each module resolve it again.

**Avoid loops that re-read the same resource.** There is no batch endpoint in
this collection — each module call is one or two HTTP requests. A loop over
200 users is 200-400 requests. If that matters for your use case, please open
an issue describing it; batching would need new modules and new CipherTrust
Manager endpoints to target.

**Use `--check` to see what a play would change** without paying for the
writes.

## Diagnosing slow plays

Ansible's own timing is the right tool, since the collection emits no metrics
of its own:

```bash
ANSIBLE_CALLBACKS_ENABLED=profile_tasks ansible-playbook site.yml
```

Then `-vvv` on the slow task to see the requests being made. A task that is
slow but makes one request is CipherTrust Manager's latency, not the
collection's.
