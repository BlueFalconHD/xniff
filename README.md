See `EXAMPLE.md` for an example of XPC sniffing.

Listener output can be emitted as JSON Lines for later analysis:

- `xniff-cli listen <pid> --jsonl > events.jsonl`
- `xniff-cli sniff-xpc <pid> <hooks.dylib> --jsonl > events.jsonl`

In `--jsonl` mode, each event includes a `call_id`; entry/exit events for the same call share the same `call_id`, so you can associate a request with its return/response.
