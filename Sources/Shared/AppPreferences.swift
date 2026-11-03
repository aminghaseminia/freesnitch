import Foundation

/// Preferences that belong to the GUI bundle but can also be changed by the
/// bundled CLI. Keeping the suite and notification name shared lets a running
/// GUI adopt a CLI change without inventing another firewall control channel.
public enum AppPreferences {
    public static let suiteName = AppConstants.bundleIdGUI
    public static let changeNotification = "io.isaaclins.freesnitch.preferences.changed"

    public enum Key {
        public static let mode = "PSMode"
        public static let filterConfigurationState = "PSFilterConfigurationState"
        public static let filterConfigurationDetail = "PSFilterConfigurationDetail"
        public static let enforcement = "PSEnforcementEnabled"
        public static let showSpeeds = "PSShowSpeedsInMenuBar"
        public static let alertsAllSpaces = "PSShowAlertsOnAllSpaces"
        /// On by default. Off makes FreeSnitch a menu-bar-only app (#145).
        public static let showDockIcon = "PSShowDockIcon"
        /// Whether Alert mode also asks about destinations an app already
        /// uses. Off by default, which is the settled #26 behaviour, but it is
        /// now a stated choice instead of a silent one (#130).
        public static let askKnownContacts = "PSAskAboutKnownContacts"
        /// Block instead of allow when the extension has no policy, an ask
        /// cannot reach a user, or a flow is not a socket flow. Off by default:
        /// fail-open is the documented contract, because a firewall that locks
        /// the user out of their own network is worse than one that misses a
        /// decision. Shared through the app group so the sandboxed extension
        /// can read the same value.
        public static let failClosed = "PSFailClosed"
    }

    public static var defaults: UserDefaults {
        // The shipped CLI runs from Contents/MacOS inside the GUI app bundle,
        // so standard already names the GUI domain. A standalone development
        // CLI needs the explicit suite instead.
        if Bundle.main.bundleIdentifier == AppConstants.bundleIdGUI {
            return UserDefaults.standard
        }
        return UserDefaults(suiteName: suiteName) ?? UserDefaults.standard
    }

    public static func bool(forKey key: String) -> Bool {
        defaults.bool(forKey: key)
    }

    /// The app-group suite shared with the network extension. The extension is
    /// sandboxed under its own bundle identifier, so it cannot read the GUI's
    /// own domain; this suite is the one place both can see.
    public static var sharedGroupDefaults: UserDefaults? {
        UserDefaults(suiteName: AppConstants.appGroup)
    }

    /// Read by the extension, written by the GUI's Settings page.
    public static var failClosed: Bool {
        get { sharedGroupDefaults?.bool(forKey: Key.failClosed) ?? false }
        set {
            sharedGroupDefaults?.set(newValue, forKey: Key.failClosed)
            sharedGroupDefaults?.synchronize()
            postChange(key: Key.failClosed, value: newValue, notify: true)
        }
    }

    public static func string(forKey key: String) -> String? {
        defaults.string(forKey: key)
    }

    public static func set(_ value: String, forKey key: String, notify: Bool = true) {
        defaults.set(value, forKey: key)
        defaults.synchronize()
        postChange(key: key, value: value, notify: notify)
    }

    public static func set(_ value: Bool, forKey key: String, notify: Bool = true) {
        defaults.set(value, forKey: key)
        defaults.synchronize()
        postChange(key: key, value: value, notify: notify)
    }

    private static func postChange(key: String, value: Any, notify: Bool) {
        guard notify else { return }
        DistributedNotificationCenter.default().postNotificationName(
            Notification.Name(changeNotification),
            object: nil,
            userInfo: [key: value],
            deliverImmediately: true
        )
    }
}
