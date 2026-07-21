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
Hex (-100) -> Raw XPC (0) -> Foundation NSXPC (100) -> Core Data XPC (200)
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

Core Data framing and operation semantics are separate. Add a focused
`CoreDataOperationDecoder` and register it in `CoreDataOperationRegistry` to
support another message code without changing the XPC message decoder.

## Known reverse-engineering work

- Map Core Data operation codes and the positional fields in each private row
  schema. Count-prefixed replies are preserved as result arrays today, but their
  row elements remain positional rather than guessed.
- Decode the opaque Core Data row/result buffer variant.
- Finish tracing Foundation's NSXPC marshal/demarshal functions in the shared
  cache. `replysig` is treated only as the Objective-C reply-block ABI; concrete
  class names and keyed properties come from the archived values themselves.
