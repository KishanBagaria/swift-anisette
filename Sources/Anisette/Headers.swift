import Foundation

extension AnisetteSystemInfo {
    /// The common Apple device headers sent with provisioning and authentication requests.
    ///
    /// - Parameters:
    ///   - identifier: The identity's UUID, as passed to `AnisetteContext.open`, `with`, or `provision`.
    ///   - date: The request time, sent in UTC.
    ///   - timeZone: Sent by abbreviation (for example `PST`); omitted if it has none.
    ///   - locale: Sent by identifier (for example `en_US`).
    public func deviceHeaders(
        identifier: UUID,
        date: Date = Date(),
        timeZone: TimeZone = .current,
        locale: Locale = .current
    ) -> [String: String] {
        let clock = ISO8601DateFormatter()
        clock.timeZone = TimeZone(secondsFromGMT: 0)
        clock.formatOptions = [.withInternetDateTime]
        var headers = [
            "X-Apple-I-MD-LU": Resources.hash(withUnsafeBytes(of: identifier.uuid) { Data($0) }),
            "X-Mme-Device-Id": identifier.uuidString.lowercased(),
            "X-MMe-Client-Info": clientInfo,
            "X-Apple-I-SRL-NO": "0",
            "X-Apple-I-Client-Time": clock.string(from: date),
            "X-Apple-Locale": locale.identifier,
        ]
        headers["X-Apple-I-TimeZone"] = timeZone.abbreviation(for: date)
        return headers
    }
}

extension AnisetteContext.OTP {
    /// The anisette headers sent with Apple authentication requests.
    ///
    /// - Parameters:
    ///   - identifier: The identity's UUID, as passed to `AnisetteContext.open`, `with`, or `provision`.
    ///   - routingInfo: The `X-Apple-I-MD-RINFO` value Apple returned when this identity was provisioned.
    ///     The caller keeps it with the provisioning state.
    ///   - system: The virtual Mac's versions, normally `AnisetteSystemInfo.current()`.
    ///   - date: The request time, sent in UTC.
    ///   - timeZone: Sent by abbreviation (for example `PST`); omitted if it has none.
    ///   - locale: Sent by identifier (for example `en_US`).
    public func headers(
        identifier: UUID,
        routingInfo: UInt64,
        system: AnisetteSystemInfo,
        date: Date = Date(),
        timeZone: TimeZone = .current,
        locale: Locale = .current
    ) -> [String: String] {
        var headers = system.deviceHeaders(identifier: identifier, date: date, timeZone: timeZone, locale: locale)
        headers["X-Apple-I-MD"] = password.base64EncodedString()
        headers["X-Apple-I-MD-M"] = machineID.base64EncodedString()
        headers["X-Apple-I-MD-RINFO"] = String(routingInfo)
        return headers
    }
}
