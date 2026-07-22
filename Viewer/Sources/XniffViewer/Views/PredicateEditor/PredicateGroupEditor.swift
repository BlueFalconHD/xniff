import SwiftUI
import XniffViewerCore

struct PredicateGroupEditor: View {
    @Binding var group: TracePredicateGroup
    let isRoot: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            groupHeader

            ForEach(Array(group.items.enumerated()), id: \.element.id) { index, _ in
                PredicateItemEditor(
                    item: itemBinding(at: index),
                    remove: { group.items.remove(at: index) }
                )
            }

            HStack(spacing: 12) {
                Button("Condition", systemImage: "plus") {
                    group.items.append(.comparison(TracePredicateComparison()))
                }
                Button("Group", systemImage: "rectangle.3.group") {
                    group.items.append(.group(TracePredicateGroup()))
                }
            }
            .buttonStyle(.borderless)
            .controlSize(.small)
        }
        .padding(isRoot ? 0 : 10)
        .background {
            if !isRoot {
                RoundedRectangle(cornerRadius: 8)
                    .fill(.quaternary.opacity(0.35))
            }
        }
        .overlay {
            if !isRoot {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(.separator)
            }
        }
    }

    private var groupHeader: some View {
        HStack(spacing: 8) {
            Text(isRoot ? "Match" : "Group matches")
                .foregroundStyle(.secondary)

            Picker("Conjunction", selection: $group.conjunction) {
                ForEach(TracePredicateConjunction.allCases) { conjunction in
                    Text(conjunction.label).tag(conjunction)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 90)

            Text("of the following")
                .foregroundStyle(.secondary)

            Toggle("Not", isOn: $group.isNegated)
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Negate this group")
        }
        .font(.callout)
    }

    private func itemBinding(at index: Int) -> Binding<TracePredicateItem> {
        Binding(
            get: { group.items[index] },
            set: { group.items[index] = $0 }
        )
    }
}

private struct PredicateItemEditor: View {
    @Binding var item: TracePredicateItem
    let remove: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            switch item {
            case .comparison:
                PredicateComparisonEditor(comparison: comparisonBinding)
            case .group:
                PredicateGroupEditor(group: groupBinding, isRoot: false)
            }

            Button("Remove", systemImage: "minus.circle", action: remove)
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("Remove this predicate")
                .padding(.top, 4)
        }
    }

    private var comparisonBinding: Binding<TracePredicateComparison> {
        Binding(
            get: {
                guard case .comparison(let comparison) = item else {
                    return TracePredicateComparison()
                }
                return comparison
            },
            set: { item = .comparison($0) }
        )
    }

    private var groupBinding: Binding<TracePredicateGroup> {
        Binding(
            get: {
                guard case .group(let group) = item else { return TracePredicateGroup() }
                return group
            },
            set: { item = .group($0) }
        )
    }
}

private struct PredicateComparisonEditor: View {
    @Binding var comparison: TracePredicateComparison

    var body: some View {
        HStack(spacing: 8) {
            Toggle("Not", isOn: $comparison.isNegated)
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Negate this condition")

            Picker("Field", selection: $comparison.field) {
                Section("Call Metadata") {
                    ForEach(TracePredicateField.all.filter { !$0.requiresBodyData }) { field in
                        Text(field.label).tag(field)
                    }
                }
                Section("Inspector Trees") {
                    ForEach(TracePredicateField.all.filter(\.requiresBodyData)) { field in
                        Text(field.label).tag(field)
                    }
                }
            }
            .labelsHidden()
            .frame(minWidth: 145, idealWidth: 180, maxWidth: 210)

            Picker("Operator", selection: $comparison.operation) {
                ForEach(TracePredicateOperator.supported(for: comparison.field.valueKind)) { operation in
                    Text(operation.label).tag(operation)
                }
            }
            .labelsHidden()
            .frame(minWidth: 125, idealWidth: 150, maxWidth: 175)

            if comparison.operation.requiresValue {
                PredicateValueEditor(
                    value: $comparison.value,
                    kind: comparison.field.valueKind
                )
            }
        }
        .onChange(of: comparison.field) { oldField, newField in
            guard oldField.valueKind != newField.valueKind else { return }
            comparison.value = .defaultValue(for: newField.valueKind)
            comparison.operation = TracePredicateOperator.supported(for: newField.valueKind)[0]
        }
        .onChange(of: comparison.operation) {
            let supported = TracePredicateOperator.supported(for: comparison.field.valueKind)
            if !supported.contains(comparison.operation) {
                comparison.operation = supported[0]
            }
        }
    }
}

private struct PredicateValueEditor: View {
    @Binding var value: TracePredicateLiteral
    let kind: TracePredicateValueKind

    var body: some View {
        switch kind {
        case .string:
            TextField("Value", text: stringBinding)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 150)
        case .number:
            TextField("Number", value: numberBinding, format: .number)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 110, idealWidth: 140)
        case .boolean:
            Picker("Value", selection: booleanBinding) {
                Text("True").tag(true)
                Text("False").tag(false)
            }
            .labelsHidden()
            .frame(width: 85)
        }
    }

    private var stringBinding: Binding<String> {
        Binding(
            get: {
                guard case .string(let value) = value else { return "" }
                return value
            },
            set: { value = .string($0) }
        )
    }

    private var numberBinding: Binding<Decimal> {
        Binding(
            get: {
                guard case .number(let value) = value else { return 0 }
                return value
            },
            set: { value = .number($0) }
        )
    }

    private var booleanBinding: Binding<Bool> {
        Binding(
            get: {
                guard case .boolean(let value) = value else { return false }
                return value
            },
            set: { value = .boolean($0) }
        )
    }
}
