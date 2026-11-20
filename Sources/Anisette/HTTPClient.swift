import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct AnisetteHTTPClient: Sendable {
    public var fetch: @Sendable (URL, Range<Int64>?) async throws -> Data

    public init(fetch: @escaping @Sendable (URL, Range<Int64>?) async throws -> Data) {
        self.fetch = fetch
    }

    public static let live = AnisetteHTTPClient { url, range in
        try await Download(url: url, range: range).run()
    }
}

/// Reject unbounded responses before accepting their bodies. In particular, a
/// server ignoring Range must not cause a restore image to fill memory or disk.
private final class Download: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let url: URL
    private let range: Range<Int64>?
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, any Error>?
    private var task: URLSessionDataTask?
    private var session: URLSession?
    private var data = Data()
    private var cancelled = false
    private var limit: Int { range.map { Int($0.count) } ?? (64 << 20) }

    init(url: URL, range: Range<Int64>?) { self.url = url; self.range = range }

    func run() async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if cancelled {
                    lock.unlock(); continuation.resume(throwing: CancellationError()); return
                }
                self.continuation = continuation
                var request = URLRequest(url: url)
                request.timeoutInterval = 120
                request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
                if let range { request.setValue("bytes=\(range.lowerBound)-\(range.upperBound - 1)", forHTTPHeaderField: "Range") }
                let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
                self.session = session
                let task = session.dataTask(with: request)
                self.task = task
                lock.unlock()
                task.resume()
            }
        } onCancel: {
            self.lock.lock()
            self.cancelled = true
            let task = self.task
            self.lock.unlock()
            task?.cancel()
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let rejection = rejection(of: response)
        completionHandler(rejection == nil ? .allow : .cancel)
        if let rejection { finish(.failure(failure(rejection))) }
    }

    private func rejection(of response: URLResponse) -> String? {
        guard let response = response as? HTTPURLResponse, response.url?.scheme == "https" else {
            return "the response was not HTTPS"
        }
        let length = response.expectedContentLength
        guard let range else {
            if response.statusCode != 200 { return "HTTP \(response.statusCode)" }
            return length <= limit ? nil : "the server announced \(length) bytes, over the \(limit)-byte limit"
        }
        if response.statusCode != 206 { return "HTTP \(response.statusCode) instead of 206 for a range request" }
        let expected = "bytes \(range.lowerBound)-\(range.upperBound - 1)/"
        let actual = response.value(forHTTPHeaderField: "Content-Range")
        if actual?.hasPrefix(expected) != true { return "Content-Range was \(actual ?? "missing"), expected \(expected)*" }
        return length < 0 || length == limit ? nil : "the server announced \(length) bytes for a \(limit)-byte range"
    }

    private func failure(_ reason: String) -> AnisetteError {
        AnisetteError("Cannot download \(url.lastPathComponent): \(reason)")
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard chunk.count <= limit - data.count else {
            dataTask.cancel(); finish(.failure(failure("the body exceeded \(limit) bytes"))); return
        }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        if let error { finish(.failure(error)) } else if range != nil && data.count != limit {
            finish(.failure(failure("the body ended after \(data.count) of \(limit) bytes")))
        } else { finish(.success(data)) }
    }

    private func finish(_ result: Result<Data, any Error>) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        let session = self.session
        self.session = nil
        task = nil
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }
}
