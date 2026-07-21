# Body inspectors

Body decoding is an ordered pipeline in `Sources/XniffViewerCore/Inspection`.
An inspector can consume the original body or name another inspector as its
parent. It returns `nil` when it does not recognize the payload. Successful
results are sorted by descending priority, so the highest-level applicable
interpretation is the viewer default while every lower-level result remains
available in the Body picker.

The built-in chain is:

```text
Raw XPC (0) -> Foundation NSXPC (100) -> Core Data XPC (200)
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
node. That is how **Show in Hex** continues to select the corresponding bytes in
the original XPC serialization after several semantic transformations.

## Known reverse-engineering work

- Map Core Data operation codes and the positional fields in each private row
  schema. Count-prefixed replies are preserved as result arrays today, but their
  row elements remain positional rather than guessed.
- Decode the opaque Core Data row/result buffer variant.
- Finish tracing Foundation's NSXPC marshal/demarshal functions in the shared
  cache. `replysig` is treated only as the Objective-C reply-block ABI; concrete
  class names and keyed properties come from the archived values themselves.
