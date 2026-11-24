import Foundation

/// Deduplicates in-flight loads per key while waking cancelled waiters immediately
/// and cancelling the underlying task when the last waiter cancels.
actor Coalescer<Key: Hashable & Sendable, Value: Sendable> {
    private let retainsValues: Bool

    init(retainsValues: Bool = true) {
        self.retainsValues = retainsValues
    }

    private struct InFlight {
        let id: UUID
        let task: Task<Void, Never>
        var waiters: [UUID: CheckedContinuation<Value, any Error>] = [:]
    }

    private enum Entry {
        case loading(InFlight)
        case loaded(Value)
    }

    private var entries: [Key: Entry] = [:]

    func load(_ key: Key, loader: @escaping @Sendable () async throws -> Value) async throws -> Value {
        try Task.checkCancellation()
        if case .loaded(let value) = entries[key] { return value }
        let waiterID = UUID()
        let entryID: UUID
        if case .loading(let existing) = entries[key] {
            entryID = existing.id
        } else {
            let id = UUID()
            let task = Task.detached(priority: Task.currentPriority) {
                do {
                    let value = try await loader()
                    await self.finish(key: key, entryID: id, result: .success(value))
                } catch {
                    await self.finish(key: key, entryID: id, result: .failure(error))
                }
            }
            entries[key] = .loading(InFlight(id: id, task: task))
            entryID = id
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.attachWaiter(key: key, entryID: entryID, waiterID: waiterID, continuation: continuation)
            }
        } onCancel: {
            Task { await self.cancelWaiter(key: key, entryID: entryID, waiterID: waiterID) }
        }
    }

    private func attachWaiter(
        key: Key,
        entryID: UUID,
        waiterID: UUID,
        continuation: CheckedContinuation<Value, any Error>
    ) {
        guard case .loading(var inflight) = entries[key], inflight.id == entryID else {
            if case .loaded(let value) = entries[key] {
                continuation.resume(returning: value)
            } else {
                continuation.resume(throwing: CancellationError())
            }
            return
        }
        if Task.isCancelled {
            if inflight.waiters.isEmpty {
                entries.removeValue(forKey: key)
                inflight.task.cancel()
            }
            continuation.resume(throwing: CancellationError())
            return
        }
        inflight.waiters[waiterID] = continuation
        entries[key] = .loading(inflight)
    }

    private func finish(key: Key, entryID: UUID, result: Result<Value, any Error>) {
        guard case .loading(let inflight) = entries[key], inflight.id == entryID else { return }
        switch result {
        case .success(let value) where retainsValues:
            entries[key] = .loaded(value)
        default:
            entries.removeValue(forKey: key)
        }
        for continuation in inflight.waiters.values {
            continuation.resume(with: result)
        }
    }

    private func cancelWaiter(key: Key, entryID: UUID, waiterID: UUID) {
        guard case .loading(var inflight) = entries[key], inflight.id == entryID else { return }
        guard let continuation = inflight.waiters.removeValue(forKey: waiterID) else { return }
        if inflight.waiters.isEmpty {
            entries.removeValue(forKey: key)
            inflight.task.cancel()
        } else {
            entries[key] = .loading(inflight)
        }
        continuation.resume(throwing: CancellationError())
    }
}
