# Predicate filtering

The viewer and `xniff-print` share one typed predicate language. The viewer edits
the predicate visually by default. Its **Text** button exposes the canonical form
for copying, pasting, or using at the command line. Right-clicking a call table
row can append predicates for that call, service, function, role, process, peer,
or completion state.

## Expressions

Predicates support nested parentheses and the boolean operators `and`, `or`, and
`not`. `and` binds more tightly than `or`.

```text
service contains "model" and (role == "request" or duration >= 25ms)
not (api == "Diagnostic" or payload.truncated == true)
```

Strings are case-insensitive. String operators are `==`, `!=`, `contains`,
`not contains`, `beginswith`, `endswith`, `matches`, `exists`, and `not exists`.
`matches` accepts a regular expression. Numbers support `==`, `!=`, `<`, `<=`,
`>`, and `>=`. Timestamp and duration literals accept `s`, `ms`, `us`/`µs`, and
`ns` units. Hexadecimal integer literals use the `0x` prefix.

A quoted string or an unrecognized standalone word is shorthand for
`any contains <value>`.

## Metadata fields

| Field | Meaning |
| --- | --- |
| `any` | Function, service, role, summary, identifiers, and event metadata |
| `call.id`, `pid`, `peer.pid` | Call and process identifiers |
| `role`, `service`, `function`, `function.id` | Call classification |
| `api`, `direction` | Captured API and entry/exit direction |
| `timestamp`, `duration` | Relative capture time in seconds |
| `complete`, `request.exists`, `response.exists` | Pairing state |
| `event.count`, `event.id`, `sequence`, `thread.id` | Event metadata |
| `return.value`, `argument`, `summary` | Function result and arguments |
| `xpc.object`, `xpc.kind`, `xpc.lifecycle` | XPC object metadata |
| `payload.count`, `payload.size`, `payload.kind`, `payload.truncated` | Payload metadata |
| `backtrace.image`, `backtrace.symbol` | Captured backtrace metadata |

Fields with multiple values match when any value satisfies a positive operator.
Negative operators such as `!=` and `not contains` require that none of the
values satisfy the corresponding positive comparison.

## Inspector tree fields

Inspector predicates lazily decode bodies only when evaluation reaches the tree
clause. Decoded results are cached per call. Metadata clauses placed first in an
`and` group can therefore reject calls without decoding their bodies.

| Field | Meaning |
| --- | --- |
| `inspector` | Inspector display name or identifier |
| `tree` | Any indexed inspector node as `side.inspector path = value` |
| `request.tree`, `response.tree` | Side-specific indexed nodes |
| `tree.path` | Structured path such as `$.NSMetadata.store` or `$.Rows[0]` |
| `tree.name` | Field or array-item name |
| `tree.value` | Searchable node value or container summary |
| `tree.number`, `tree.boolean` | Typed numeric and Boolean node values |
| `tree.type` | Decoded object type |

Inspector detail fields are indexed beneath `$details`. Every applicable
inspector is searchable, including Raw XPC, Foundation NSXPC, Swift XPC Codable,
and Core Data—not only the currently selected visual inspector.
Separate tree clauses are independent existential matches. Use the combined
`tree`, `request.tree`, or `response.tree` text when a path and value must match
the same node.

```text
inspector == "Core Data" and request.tree contains "NSMetadata.store = ScreenTime"
tree.path beginswith "$.Rows" and tree.value matches "account|person"
response.tree contains "Result count = 0"
```

## Terminal usage

Pass the text representation with `--predicate` or `-p`. Repeating the option
combines the expressions with `and`.

```sh
build/xniff-print \
  --predicate 'pid == 42 and role == "request"' \
  --predicate 'service contains "model" or duration >= 25ms' \
  /tmp/screentime.xniff
```
