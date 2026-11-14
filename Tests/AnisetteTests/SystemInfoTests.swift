#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

struct SystemInfoTests {
    @Test func headersAndGuestUseTheSameMetadata() throws {
        let system = AnisetteSystemInfo(productVersion: "30.2.1", buildVersion: "29C123", darwinVersion: "30.2.0",
                                        cfNetworkVersion: "4000.2.3.4", authKitVersion: "2", akdVersion: "3.0")
        #expect(system.clientInfo == "<MacBookPro13,3> <Mac OS X;30.2.1;29C123> <com.apple.AuthKit/2 (com.apple.akd/3.0)>")
        #expect(system.akdUserAgent == "akd/3.0 CFNetwork/4000.2.3.4 Darwin/30.2.0")
        #expect(system.sysctlValue(for: "hw.model") == system.model)
        #expect(system.sysctlValue(for: "kern.osversion") == "29C123")
        #expect(system.sysctlValue(for: "kern.osrelease") == "30.2.0")
        #expect(system.sysctlValue(for: "kern.osproductversion") == "30.2.1")
        #expect(system.sysctlValue(for: "kern.ostype") == "Darwin")
        #expect(system.sysctlValue(for: "unknown") == nil)
    }

    @Test func otpHeadersAreDeterministic() throws {
        let system = AnisetteSystemInfo(productVersion: "30.2.1", buildVersion: "29C123", darwinVersion: "30.2.0",
                                        cfNetworkVersion: "4000.2.3.4", authKitVersion: "2", akdVersion: "3.0")
        let otp = AnisetteContext.OTP(machineID: Data("mid".utf8), password: Data("otp".utf8), provisioningState: Data())
        let identifier = try #require(UUID(uuidString: "00010203-0405-0607-0809-0A0B0C0D0E0F"))
        let timeZone = try #require(TimeZone(identifier: "America/Los_Angeles"))
        let winterDate = Date(timeIntervalSince1970: 1_700_000_000.75)
        let summerDate = Date(timeIntervalSince1970: 1_690_000_000)
        // Foundation uses PST/PDT on macOS and GMT-8/GMT-7 on Linux.
        // The header follows Foundation's abbreviation for the requested date.
        let winterAbbreviation = try #require(timeZone.abbreviation(for: winterDate))
        let summerAbbreviation = try #require(timeZone.abbreviation(for: summerDate))
        #expect(timeZone.secondsFromGMT(for: winterDate) == -8 * 3600)
        #expect(timeZone.secondsFromGMT(for: summerDate) == -7 * 3600)
        #expect(winterAbbreviation != summerAbbreviation)
        let headers = otp.headers(identifier: identifier, routingInfo: 17106176, system: system,
                                  date: winterDate,
                                  timeZone: timeZone,
                                  locale: Locale(identifier: "en_US"))
        #expect(headers == [
            "X-Apple-I-MD": "b3Rw",
            "X-Apple-I-MD-M": "bWlk",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991",
            "X-Mme-Device-Id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
            "X-MMe-Client-Info": "<MacBookPro13,3> <Mac OS X;30.2.1;29C123> <com.apple.AuthKit/2 (com.apple.akd/3.0)>",
            "X-Apple-I-SRL-NO": "0",
            "X-Apple-I-Client-Time": "2023-11-14T22:13:20Z",
            "X-Apple-I-TimeZone": winterAbbreviation,
            "X-Apple-Locale": "en_US",
        ])
        let summer = otp.headers(identifier: identifier, routingInfo: 0, system: system,
                                 date: summerDate,
                                 timeZone: timeZone,
                                 locale: Locale(identifier: "de_DE"))
        #expect(summer["X-Apple-I-TimeZone"] == summerAbbreviation)
        #expect(summer["X-Apple-Locale"] == "de_DE")
        #expect(summer["X-Apple-I-Client-Time"] == "2023-07-22T04:26:40Z")
    }
}
#endif
