# Body inspectors

Body decoding is an ordered pipeline in `Sources/XniffViewerCore/Inspection`.
An inspector can consume the original body or name another inspector as its
parent. It returns `nil` when it does not recognize the payload. Successful
results are sorted by descending priority, so the highest-level applicable
interpretation is the viewer default while every lower-level result remains
available in the Body picker.

An inspection returns typed content (`tree` or `bytes`) and optional structured
detail rows. The viewer owns their presentation; inspectors do not provide
custom title-bar text or icons.

The built-in chain is:

```text
Hex (-100) -> Raw XPC (0) -> Foundation NSXPC (100) -> Core Data / NSXPCStore (200)
                         \-> Swift XPC Codable (150)
```

To add a layer:

1. Add one focused file under `Sources/XniffViewerCore/Inspection`.
2. Conform a stateless `Sendable` type to `TraceBodyInspector`.
3. Give it a stable identifier, its parent's identifier, and a priority above
   its parent.
4. Read the parent with `context.inspection(parentIdentifier)` and return a
   `BodyInspection` only when the protocol is recognized.
5. Register it in `BodyInspectorRegistry.standard` and add a fixture test.

Inspectors should preserve `TraceValue.sourced` wrappers when replacing a tree
node. A tree item's context menu uses that range for **Copy Hex** and **View in
_parent_**. Parent navigation selects the exact range when possible, then falls
back to the smallest containing or overlapping node. Since Hex is the root
inspection, the same chain also supports byte highlighting without a separate
Hex tab.

Core Data framing and operation semantics are separate. `NSCoreDataXPCMessage`
is the envelope of Core Data's private `NSXPCStore` protocol; it is not part of
Foundation NSXPC. Add a focused `CoreDataOperationDecoder` and register it in
`CoreDataOperationRegistry` to support another message code without changing
the envelope decoder. Reply interpretation can use the paired request through
`BodyInspectorContext.counterpartBody`.

Structured SQL fetch results are only partly self-describing. The wire header
contains result-buffer offsets, sizes, row links, SQL entity IDs, and primary
keys. Property boundaries, types, and names are omitted. Apple's decoder rebuilds
those from the original fetch request and the `NSXPCStore`'s managed-object/SQL
model. The viewer therefore exposes the structural row data and identifies the
entity from the paired request, but does not guess property values without a
model. Inline object-fault replies are labeled as model-ordered property slots
for the same reason.

## Foundation NSXPC wire format

The Foundation inspector follows the marshal and unmarshal paths in the loaded
Foundation shared-cache image. `NSXPCEncoder` writes `root` as an inline
`bplist17` array with exactly these protocol fields:

```text
request: [selector string, Objective-C method signature, argument array]
reply:   [null,            reply-block signature,      argument array]
```

Request arguments correspond to the method signature after implicit `self` and
`_cmd`; reply arguments correspond to the block signature after its implicit
block parameter. `replysig` on a request is the ABI signature used to validate
and construct the eventual reply block. The parser handles complete nested
Objective-C type tokens rather than extracting quoted class names heuristically.

Objects encoded out of line appear in the outer `ool` XPC array. Their archived
wrapper contains a `$xpc` integer, which is an index into that array. The
Foundation tree resolves the index while retaining both it and the typed wrapper.

## Swift XPC Codable wire format

libSwiftXPC version 1 stores a breadth-first serialized `EncodingGraph` in the
outer XPC dictionary's `_CodableBody` data value. Graph tags preserve Codable's
keyed, unkeyed, and single-value containers and its complete scalar type set.
Container-reference tags declare numbered nodes; container-end tags advance to
those nodes in numeric order.

The version-1 tags are:

| Tag | Meaning |
| ---: | --- |
| `0x00` | `nil` |
| `0x01` / `0x02` | `true` / `false` |
| `0x03` | UTF-8 string |
| `0x04` / `0x05` | `Float` / `Double` |
| `0x06`–`0x0A` | `Int`, `Int8`, `Int16`, `Int32`, `Int64` |
| `0x0B`–`0x0F` | `UInt`, `UInt8`, `UInt16`, `UInt32`, `UInt64` |
| `0x10` / `0x11` | Empty / string coding key |
| `0x12` | `_CodableOutOfLine` index |
| `0x13` | Container metadata (`0x0A` keyed, `0x0B` unkeyed, `0x0C` single-value) |
| `0x14` | Numbered container reference |
| `0x15` | Finish the current container and advance to the next node |
| `0x16` | Invalid/dangling-container sentinel |

`_CodableOutOfLine` carries `XPCData` values referenced by a dedicated graph tag.
`_CodableOutOfLine4CodableObject` carries general `XPCCodableObject` values. The
latter are encoded in a single-value container as an integer array index, so the
viewer resolves them only when exactly one graph location can refer to that
index. The resolved tree keeps both the index and the raw XPC value.

The observed `f` bits are:

| Bit | Meaning |
| ---: | --- |
| `0x1` | Foundation message |
| `0x4` | Control frame |
| `0x8` | Release exported proxy |
| `0x10` | Progress frame |
| `0x20` | Request expects a reply |
| `0x40` | Request carries progress |
| `0x80` | Method returns that progress |
| `0x10000` | Cancel progress |
| `0x20000` | Pause progress |
| `0x40000` | Resume progress |

Proxy-release and progress control frames intentionally have no `root`. Normal
XPC replies also do not need request metadata such as `f`, `proxynum`, or
`sequence`; reply routing associates them with the outstanding sequence.

## Known reverse-engineering work

- Accept a compiled managed-object model (`.mom`/`.momd`) and use it to assign
  property names and types to NSXPCStore result slots and SQL property storage.
