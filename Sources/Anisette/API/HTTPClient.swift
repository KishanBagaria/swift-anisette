import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// An asynchronous HTTPS client used by `swift-anisette` to fetch pinned Apple restore-image ranges
/// and the native Unicorn archive.
///
/// Provide a custom instance via ``AnisetteConfiguration/httpClient`` to inject proxies, caching,
/// or offline fixtures in tests. Every byte returned is verified against pinned cryptographic hashes.
public struct AnisetteHTTPClient: Sendable {
    /// Fetches either the full resource (`range == nil`) or an exact half-open byte range
    /// (`lowerBound..<upperBound`) from `url`.
    public var fetch: @Sendable (URL, Range<Int64>?) async throws -> Data

    /// Creates an HTTP client backed by the given fetch closure.
    public init(fetch: @escaping @Sendable (URL, Range<Int64>?) async throws -> Data) {
        self.fetch = fetch
    }

    /// The default live HTTPS client backed by a shared ephemeral `URLSession`.
    ///
    /// Enforces HTTPS on initial requests and redirects, validates `Content-Range` and body-size limits
    /// before buffering, propagates cooperative task cancellation as `CancellationError`, and retries
    /// transient network or server errors with bounded backoff.
    public static let live = AnisetteHTTPClient { url, range in
        try await performWithRetry(for: url) {
            try await Download(url: url, range: range).run()
        }
    }
}

extension AnisetteHTTPClient {
    struct RetryableError: Error {
        let underlying: AnisetteError
    }

    /// Accumulates streamed response chunks while enforcing a hard byte limit.
    struct BodyBuffer: Sendable {
        let limit: Int
        private(set) var data = Data()

        mutating func append(_ chunk: Data, for url: URL) -> Result<Void, AnisetteError> {
            guard chunk.count <= limit - data.count else {
                return .failure(AnisetteHTTPClient.failure(for: url, reason: "the body exceeded \(limit) bytes"))
            }
            data.append(chunk)
            return .success(())
        }
    }

    static let defaultLimit = 64 << 20
    static let defaultRetryBackoff: [Duration] = [.milliseconds(250), .milliseconds(750)]

    static func rangeHeader(for range: Range<Int64>) -> String {
        "bytes=\(range.lowerBound)-\(range.upperBound - 1)"
    }

    static func failure(for url: URL, reason: String) -> AnisetteError {
        AnisetteError("Cannot download \(url.lastPathComponent): \(reason)")
    }

    static func wrapError(_ error: any Error, for url: URL) -> any Error {
        if error is CancellationError || error is AnisetteError { return error }
        return failure(for: url, reason: error.localizedDescription)
    }

    static func isRetryableStatus(_ statusCode: Int) -> Bool {
        switch statusCode {
        case 429, 500, 502, 503, 504: return true
        default: return false
        }
    }

    static func isRetryableError(_ error: any Error) -> Bool {
        if error is CancellationError || error is AnisetteError { return false }
        guard let urlError = error as? URLError else { return false }
        switch urlError.code {
        case .timedOut, .networkConnectionLost, .cannotConnectToHost, .cannotFindHost,
             .dnsLookupFailed, .notConnectedToInternet, .cannotLoadFromNetwork:
            return true
        default:
            return false
        }
    }

    static func validateResponse(
        _ response: URLResponse,
        for url: URL,
        range: Range<Int64>?,
        limit: Int
    ) -> Result<Void, AnisetteError> {
        guard let http = response as? HTTPURLResponse, http.url?.scheme?.lowercased() == "https" else {
            return .failure(failure(for: url, reason: "the response was not HTTPS"))
        }
        let length = http.expectedContentLength
        if let range {
            return validateRangeResponse(http, for: url, range: range, length: length, limit: limit)
        }
        if http.statusCode != 200 {
            return .failure(failure(for: url, reason: "HTTP \(http.statusCode)"))
        }
        if length > Int64(limit) {
            return .failure(failure(for: url, reason: "the server announced \(length) bytes, over the \(limit)-byte limit"))
        }
        return .success(())
    }

    private static func validateRangeResponse(
        _ http: HTTPURLResponse,
        for url: URL,
        range: Range<Int64>,
        length: Int64,
        limit: Int
    ) -> Result<Void, AnisetteError> {
        if http.statusCode != 206 {
            return .failure(failure(for: url, reason: "HTTP \(http.statusCode) instead of 206 for a range request"))
        }
        let expected = "bytes \(range.lowerBound)-\(range.upperBound - 1)/"
        let actual = http.value(forHTTPHeaderField: "Content-Range")
        if actual?.hasPrefix(expected) != true {
            return .failure(failure(for: url, reason: "Content-Range was \(actual ?? "missing"), expected \(expected)*"))
        }
        if length >= 0 && length != Int64(limit) {
            return .failure(failure(for: url, reason: "the server announced \(length) bytes for a \(limit)-byte range"))
        }
        return .success(())
    }

    static func validateRedirect(
        _ newRequest: URLRequest,
        for url: URL,
        range: Range<Int64>?
    ) -> Result<URLRequest, AnisetteError> {
        guard newRequest.url?.scheme?.lowercased() == "https" else {
            return .failure(failure(for: url, reason: "redirect target was not HTTPS"))
        }
        var redirected = newRequest
        applyHeaders(to: &redirected, range: range)
        return .success(redirected)
    }

    static func applyHeaders(to request: inout URLRequest, range: Range<Int64>?) {
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if let range {
            request.setValue(rangeHeader(for: range), forHTTPHeaderField: "Range")
        }
    }

    static func performWithRetry(
        for url: URL,
        backoff: [Duration] = defaultRetryBackoff,
        attempt: () async throws -> Data
    ) async throws -> Data {
        var delays = backoff[...]
        while true {
            try Task.checkCancellation()
            do {
                return try await attempt()
            } catch let retryable as RetryableError {
                guard let delay = delays.popFirst() else { throw retryable.underlying }
                try await Task.sleep(for: delay)
            } catch {
                guard isRetryableError(error), let delay = delays.popFirst() else { throw wrapError(error, for: url) }
                try await Task.sleep(for: delay)
            }
        }
    }
}

/// Shares one ephemeral `URLSession` across ranged downloads so TCP/TLS/HTTP2 connections are reused.
private final class SessionRouter: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    static let shared = SessionRouter()
    private let lock = NSLock()
    private var downloads: [Int: Download] = [:]
    private var session: URLSession?

    func register(_ download: Download, request: URLRequest) -> URLSessionDataTask {
        lock.lock()
        let activeSession: URLSession
        if let existing = session {
            activeSession = existing
        } else {
            let created = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
            session = created
            activeSession = created
        }
        let task = activeSession.dataTask(with: request)
        downloads[task.taskIdentifier] = download
        lock.unlock()
        return task
    }

    private func download(for task: URLSessionTask) -> Download? {
        lock.lock()
        defer { lock.unlock() }
        return downloads[task.taskIdentifier]
    }

    private func removeDownload(for task: URLSessionTask) -> Download? {
        lock.lock()
        defer { lock.unlock() }
        return downloads.removeValue(forKey: task.taskIdentifier)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let download = download(for: task) else {
            completionHandler(nil)
            return
        }
        download.handleRedirect(request, task: task, completionHandler: completionHandler)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let download = download(for: dataTask) else {
            completionHandler(.cancel)
            return
        }
        download.handleResponse(response, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        download(for: dataTask)?.handleChunk(data, task: dataTask)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        removeDownload(for: task)?.handleCompletion(error: error)
    }
}

/// Reject unbounded responses before accepting their bodies. In particular, a
/// server ignoring Range must not cause a restore image to fill memory or disk.
private final class Download: @unchecked Sendable {
    private let url: URL
    private let range: Range<Int64>?
    private let limit: Int
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, any Error>?
    private var task: URLSessionDataTask?
    private var buffer: AnisetteHTTPClient.BodyBuffer
    private var cancelled = false

    init(url: URL, range: Range<Int64>?) {
        self.url = url
        self.range = range
        let resolvedLimit = range.map { Int($0.count) } ?? AnisetteHTTPClient.defaultLimit
        self.limit = resolvedLimit
        self.buffer = AnisetteHTTPClient.BodyBuffer(limit: resolvedLimit)
    }

    func run() async throws -> Data {
        guard url.scheme?.lowercased() == "https" else {
            throw AnisetteHTTPClient.failure(for: url, reason: "the URL was not HTTPS")
        }
        if let range {
            try require(range.lowerBound >= 0 && range.upperBound >= range.lowerBound,
                        "Invalid byte range for \(url.lastPathComponent)")
            if range.isEmpty { return Data() }
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if cancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.continuation = continuation
                var request = URLRequest(url: url)
                request.timeoutInterval = 120
                AnisetteHTTPClient.applyHeaders(to: &request, range: range)
                let dataTask = SessionRouter.shared.register(self, request: request)
                self.task = dataTask
                lock.unlock()
                dataTask.resume()
            }
        } onCancel: {
            self.cancel()
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let activeTask = task
        task = nil
        let pending = continuation
        continuation = nil
        lock.unlock()
        activeTask?.cancel()
        pending?.resume(throwing: CancellationError())
    }

    func handleRedirect(
        _ newRequest: URLRequest,
        task: URLSessionTask,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        switch AnisetteHTTPClient.validateRedirect(newRequest, for: url, range: range) {
        case .success(let allowed):
            completionHandler(allowed)
        case .failure(let error):
            completionHandler(nil)
            task.cancel()
            finish(.failure(error))
        }
    }

    func handleResponse(
        _ response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        switch AnisetteHTTPClient.validateResponse(response, for: url, range: range, limit: limit) {
        case .success:
            completionHandler(.allow)
        case .failure(let error):
            completionHandler(.cancel)
            let statusCode = (response as? HTTPURLResponse)?.statusCode
            if let statusCode, AnisetteHTTPClient.isRetryableStatus(statusCode) {
                finish(.failure(AnisetteHTTPClient.RetryableError(underlying: error)))
            } else {
                finish(.failure(error))
            }
        }
    }

    func handleChunk(_ chunk: Data, task: URLSessionDataTask) {
        lock.lock()
        if cancelled || continuation == nil {
            lock.unlock()
            return
        }
        let result = buffer.append(chunk, for: url)
        lock.unlock()
        if case .failure(let error) = result {
            task.cancel()
            finish(.failure(error))
        }
    }

    func handleCompletion(error: (any Error)?) {
        lock.lock()
        let wasCancelled = cancelled
        let finishedData = buffer.data
        lock.unlock()
        if wasCancelled {
            finish(.failure(CancellationError()))
        } else if let error {
            finish(.failure(error))
        } else if range != nil && finishedData.count != limit {
            finish(.failure(AnisetteHTTPClient.failure(
                for: url,
                reason: "the body ended after \(finishedData.count) of \(limit) bytes"
            )))
        } else {
            finish(.success(finishedData))
        }
    }

    private func finish(_ result: Result<Data, any Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        task = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}
