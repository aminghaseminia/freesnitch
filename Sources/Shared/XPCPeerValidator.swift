import Foundation
import Security

/// Validates callers for XPC listeners that can change FreeSnitch state.
/// The same validator is used by the privileged helper and the network
/// extension so their trust boundary cannot drift.
public enum XPCPeerValidator {
    /// The only application identities permitted to use the privileged XPC
    /// surfaces. Keep this allowlist here, rather than copying a code
    /// requirement into each listener.
    ///
    /// The CLI is deliberately absent. It is a world-executable binary with no
    /// authentication of its own, so trusting it made any local process - not
    /// the human - the authority behind a system-wide firewall: an unprivileged
    /// process could run `freesnitch enforcement off --yes` or point the root
    /// DNS proxy at its own DoH upstream. Privileged mutations are the GUI's
    /// job because only the GUI is launched and driven by the logged-in user.
    public static let permittedPeerIdentifiers: [String] = [
        AppConstants.bundleIdGUI
    ]

    /// Return true only for the signed FreeSnitch GUI or CLI. Ad-hoc/local
    /// builds remain usable during development, matching the existing helper
    /// behavior. The bypass is inactive as soon as this process has a team ID.
    public static func isTrustedGUI(_ connection: NSXPCConnection) -> Bool {
        trustedPeer(connection, requirement: peerRequirement())
    }

    /// Used by the extension to keep a CLI inspection connection from taking
    /// ownership of the GUI connection that receives interactive alerts.
    /// Ad-hoc clients cannot become a Developer ID CLI, so this only affects
    /// signed builds where the identifier can be read reliably.
    public static func isCLI(_ connection: NSXPCConnection) -> Bool {
        let id = identifier(of: connection)
        return id == AppConstants.bundleIdCLI || id == "FreeSnitchCLI"
    }

    /// Read the signed bundle identifier of an incoming peer when available.
    /// Ad-hoc builds still carry their target identifier in the code object.
    public static func identifier(of connection: NSXPCConnection) -> String? {
        guard let code = guestCode(for: connection) else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoIdentifier as String] as? String
    }

    /// Construct the code requirements used by the privileged XPC
    /// listeners. Keep this in shared code so the helper and extension cannot
    /// silently accept different client identities.
    private static func peerRequirement() -> SecRequirement? {
        requirement(forIdentifiers: permittedPeerIdentifiers)
    }

    /// Builds the Apple-anchored, team-pinned requirement for a set of bundle
    /// identifiers. Public so the extension's own-traffic exemption uses the
    /// same requirement instead of a second copy that can drift.
    public static func requirement(forIdentifiers identifiers: [String]) -> SecRequirement? {
        let identifierClause = identifiers
            .map { "identifier \"\($0)\"" }
            .joined(separator: " or ")
        let requirementText = "anchor apple generic"
            + " and (\(identifierClause))"
            + " and certificate leaf[subject.OU] = \"\(AppConstants.teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }

    private static func trustedPeer(
        _ connection: NSXPCConnection,
        requirement: SecRequirement?
    ) -> Bool {
        switch selfSigningTeam {
        case .failure:
            // We could not read our own signature. That should never happen,
            // so treat it as hostile rather than waving every client through.
            return false
        case .success(let team) where team == nil:
            // An ad-hoc build has no team to pin, so the requirement above
            // would accept any process that claims the identifier string.
            // Restrict the development exemption to the GUI inside this same
            // bundle: another binary cannot put itself there without write
            // access to the app being trusted.
            return adHocPeerIsOurGUI(connection)
        case .success:
            break
        }

        guard let code = guestCode(for: connection),
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// Development-only exemption for an unsigned app. Both halves of the
    /// comparison are real bundle identities on disk, not identifiers a caller
    /// can choose.
    private static func adHocPeerIsOurGUI(_ connection: NSXPCConnection) -> Bool {
        guard identifier(of: connection) == AppConstants.bundleIdGUI,
              let peerApp = containingApp(of: connection),
              let selfApp = AppBundleIdentity.containingAppURL else { return false }
        return peerApp.resolvingSymlinksInPath().standardizedFileURL.path
            == selfApp.resolvingSymlinksInPath().standardizedFileURL.path
    }

    /// The .app that contains the peer executable, read from its code object so
    /// a reused pid cannot substitute another process.
    private static func containingApp(of connection: NSXPCConnection) -> URL? {
        guard let code = guestCode(for: connection) else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var path: CFURL?
        guard SecCodeCopyPath(staticCode, [], &path) == errSecSuccess, let path else {
            return nil
        }
        return AppBundleIdentity.containingAppURL(for: path as URL)
    }

    private static func guestCode(for connection: NSXPCConnection) -> SecCode? {
        var code: SecCode?
        let attributes: [String: Any]
        if let tokenData = auditTokenData(for: connection) {
            attributes = [kSecGuestAttributeAudit as String: tokenData]
        } else {
            attributes = [kSecGuestAttributePid as String: connection.processIdentifier]
        }
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    /// NSXPCConnection exposes the audit token only through KVC; fall back to
    /// the (racier) pid when that is unavailable.
    private static func auditTokenData(for connection: NSXPCConnection) -> Data? {
        guard connection.responds(to: NSSelectorFromString("auditToken")) else { return nil }
        guard let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var raw = audit_token_t()
        value.getValue(&raw, size: MemoryLayout<audit_token_t>.size)
        return withUnsafeBytes(of: &raw) { Data($0) }
    }

    /// This process's team identifier: `nil` for an ad-hoc/local build, or a
    /// failure if its signature cannot be read at all.
    private static let selfSigningTeam: Result<String?, NSError> = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -1))
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -2))
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode,
                                            SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: -3))
        }
        let team = dict["teamid"] as? String
        return .success((team?.isEmpty ?? true) ? nil : team)
    }()
}
