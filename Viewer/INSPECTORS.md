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
