import Foundation

final class BlocklistManager: @unchecked Sendable {
    /// The result of reading one IP feed. A failure is a reason, never an
    /// empty body: a feed that could not be fetched has not become empty.
    enum IPFeedFetchResult: Sendable {
        case body(String)
        case failure(String)
    }

    private let store: RuleStore
    private(set) var domains: Set<String> = []
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.blocklists")
    var onUpdate: ((Int) -> Void)?

    /// Address feeds are a separate kind of list with a separate storage key,
    /// a separate matcher, and a separate enforcement point. Nothing here ever
    /// touches `domains`, and nothing in the domain path ever reads these.
    static let ipFeedsSettingKey = "ip_blocklists"
    private var ipSet: IPBlocklistSet = .empty
    private var ipFeedsCache: [IPBlocklistFeed]?

    /// Called after every IP feed refresh with the newly built set. Wiring
    /// this is what pushes address blocking into pf.
    var onIPBlocklistUpdate: ((IPBlocklistSet, [IPBlocklistFeed]) -> Void)?

    /// Test seam. When set, feeds are read through this instead of the
    /// network, so feed handling can be exercised deterministically.
    var ipFeedFetcher: (@Sendable (IPBlocklistFeed) async -> IPFeedFetchResult)?

    init(store: RuleStore) {
        self.store = store
    }

    func refresh() async {
        let lists = store.allBlocklists().filter { $0.enabled }
        var merged: Set<String> = []
        await withTaskGroup(of: (BlocklistInfo, Set<String>?).self) { group in
            for list in lists {
                group.addTask { (list, await self.fetch(list)) }
            }
            for await (list, downloaded) in group {
                let edits = store.blocklistEdits(id: list.id)
                var set: Set<String>
                if let downloaded {
                    set = downloaded
                } else {
                    // A failed refresh keeps what the last successful download
                    // installed. Dropping it made a single unreachable feed -
                    // or every feed during an outage - silently turn blocking
                    // off, and the merged set below is the only thing the DNS
                    // proxy consults.
                    set = self.store.blocklistDomainSet(blocklistID: list.id)
                    PSLog.error(PSLog.dns,
                                "blocklist \(list.name) could not be refreshed; keeping \(set.count) stored entries")
                }
                // Hand edits are reapplied after every download, which is the
                // whole reason they are stored apart from the entries (#97).
                set.formUnion(edits.added)
                set.subtract(edits.removed)
                merged.formUnion(set)
                guard downloaded != nil else { continue }
                var updated = list
                updated.entryCount = set.count
                updated.lastUpdated = Date()
                try? self.store.updateBlocklist(updated)
                // Kept per list, on disk, so the GUI can ask what is on a list
                // without anyone holding one in memory (#79). A failure here
                // costs the browsable copy, never the blocking itself, which
                // works off the merged set below.
                do {
                    try self.store.replaceBlocklistEntries(blocklistID: list.id, domains: Array(set))
                } catch {
                    PSLog.error(PSLog.helper,
                                "blocklist entries for \(list.name) could not be stored: \(error.localizedDescription)")
                }
            }
        }
        queue.sync { self.domains = merged }
        onUpdate?(merged.count)
    }

    /// Rebuilds the matching set from what is already stored, without touching
    /// the network. A hand edit changes what should be blocked immediately;
    /// waiting for the next scheduled download would leave a name the user just
    /// removed blocked for hours (#97).
    func rebuildFromStore() {
        var merged: Set<String> = []
        for list in store.allBlocklists() where list.enabled {
            var offset = 0
            while true {
                let page = store.blocklistEntries(blocklistID: list.id,
                                                  search: "",
                                                  offset: offset,
                                                  limit: BlocklistEntryQuery.maximumLimit)
                merged.formUnion(page.entries)
                offset += page.entries.count
                if page.entries.isEmpty || offset >= page.total { break }
            }
        }
        queue.sync { self.domains = merged }
        onUpdate?(merged.count)
    }

    /// `nil` means the download failed; an empty set means the source really
    /// carried no entries.
    private func fetch(_ list: BlocklistInfo) async -> Set<String>? {
        // A hand-written list has no source. It has not failed to download;
        // there is nothing to download, and its entries are its edits (#97).
        if list.url.trimmingCharacters(in: .whitespaces).isEmpty { return [] }
        let url: URL
        do {
            // Re-validate here as well as in the GUI store: a legacy or
            // directly inserted database row must not be able to turn the root
            // helper into a cleartext fetcher.
            url = try BlocklistURLValidator.validate(list.url)
        } catch {
            PSLog.error(PSLog.dns, "blocklist \(list.name) has an invalid URL: \(error.localizedDescription)")
            return nil
        }
        guard !Self.isForbiddenFetchHost(url.host) else {
            PSLog.error(PSLog.dns,
                        "SECURITY: refusing to fetch blocklist \(list.name) from a loopback or link-local host")
            return nil
        }
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.setValue("FreeSnitch/0.1", forHTTPHeaderField: "User-Agent")
        do {
            // `data(for:)` allocates the complete body before any check can
            // run. AsyncBytes lets the byte ceiling stop a hostile or corrupt
            // feed instead of letting it exhaust the helper that also serves
            // DNS and holds the firewall rules.
            let (bytes, response) = try await URLSession.shared.bytes(for: req)
            // Without this check an error page parses into junk "domains":
            // GitHub's 404 body alone yields an entry called "Found".
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                PSLog.error(PSLog.dns, "blocklist \(list.name) returned HTTP \(http.statusCode)")
                return nil
            }
            var data = Data()
            data.reserveCapacity(1 << 20)
            for try await byte in bytes {
                guard data.count < Self.maximumFeedBytes else {
                    PSLog.error(PSLog.dns,
                                "blocklist \(list.name) is larger than the \(Self.maximumFeedBytes) byte limit")
                    return nil
                }
                data.append(byte)
            }
            guard let text = String(data: data, encoding: .utf8) else { return nil }
            return parse(text)
        } catch {
            PSLog.error(PSLog.dns, "blocklist fetch failed: \(list.name) - \(error)")
            return nil
        }
    }

    /// A HOSTS list is text; 32 MB is far beyond any real one and keeps a
    /// hostile feed from becoming an unbounded allocation.
    static let maximumFeedBytes = 32 * 1024 * 1024

    /// The helper fetches as root, and a blocklist URL can arrive through an
    /// imported profile as well as from the user. Refuse the machine's own
    /// services, the LAN and the cloud metadata address so a profile cannot
    /// turn the daemon into an internal HTTP client.
    private static func isForbiddenFetchHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased(), !host.isEmpty else { return true }
        if host == "localhost" || host.hasSuffix(".localhost") { return true }
        for suffix in [".local", ".internal", ".lan", ".home.arpa"] where host.hasSuffix(suffix) {
            return true
        }
        if host.contains(":") {
            if host == "::1" || host == "::" { return true }
            if host.hasPrefix("fc") || host.hasPrefix("fd") { return true }          // fc00::/7
            if host.hasPrefix("fe8") || host.hasPrefix("fe9")
                || host.hasPrefix("fea") || host.hasPrefix("feb") { return true }    // fe80::/10
            if host.hasPrefix("ff") { return true }                                   // ff00::/8
            return false
        }
        let octets = host.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }) else { return false }
        let a = octets[0], b = octets[1]
        if a == 0 || a == 10 || a == 127 { return true }              // this host, private
        if a == 169 && b == 254 { return true }                        // link-local, metadata
        if a == 172 && (16...31).contains(b) { return true }           // private
        if a == 192 && b == 168 { return true }                        // private
        if a == 100 && (64...127).contains(b) { return true }          // CGNAT
        if a >= 224 { return true }                                    // multicast, reserved
        return false
    }

    private func parse(_ text: String) -> Set<String> {
        var out: Set<String> = []
        out.reserveCapacity(50_000)
        for raw in text.split(separator: "\n") {
            // Trimming newlines as well keeps CRLF lists usable: a trailing
            // "\r" used to survive into the entry, so a whole Windows-format
            // feed loaded with zero effective matches.
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            // "[Adblock Plus]" heads every Adblock-syntax list.
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if parts.isEmpty { continue }
            // The first token is the entry. `parts.last` used to take a
            // trailing comment token, so "example.com # tracker" blocked
            // "tracker" and left the real name unfiltered.
            var host = parts[0]
            if parts.count >= 2, (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::1") {
                host = parts[1]
            }
            if host.hasPrefix("||") {
                let idx = host.firstIndex(of: "^") ?? host.endIndex
                host = String(host[host.index(host.startIndex, offsetBy: 2)..<idx])
            }
            host = host.lowercased()
            if host.contains("/") { continue }
            if host == "localhost" || host == "0.0.0.0" || host == "broadcasthost" { continue }
            if host.isEmpty || host.utf8.count > 253 { continue }
            // Control characters never belong in a name, and a feed is
            // untrusted input that later reaches logs and the UI.
            if host.utf8.contains(where: { $0 < 0x21 || $0 == 0x7F }) { continue }
            out.insert(host)
        }
        return out
    }

    // MARK: - IP and CIDR feeds

    /// The configured address feeds, seeded from the catalog the first time.
    /// Persisted next to, never inside, the domain blocklist table.
    func ipFeeds() -> [IPBlocklistFeed] {
        if let cached = queue.sync(execute: { ipFeedsCache }) { return cached }
        let stored = store.getSetting(BlocklistManager.ipFeedsSettingKey)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([IPBlocklistFeed].self, from: $0) }
        let feeds = stored ?? IPBlocklistCatalog.defaults
        queue.sync { ipFeedsCache = feeds }
        return feeds
    }

    /// Enables or disables one address feed. Returns false when the id is
    /// unknown, so a caller can answer honestly instead of silently doing
    /// nothing.
    @discardableResult
    func setIPFeedEnabled(idString: String, enabled: Bool) -> Bool {
        var feeds = ipFeeds()
        guard let index = feeds.firstIndex(where: { $0.id.uuidString == idString }) else { return false }
        feeds[index].enabled = enabled
        persistIPFeeds(feeds)
        return true
    }

    /// Downloads every enabled address feed and rebuilds the matcher.
    ///
    /// Fail open, in both directions: a feed that cannot be fetched, is too
    /// large, or parses to nothing usable contributes no entries and records
    /// why, and a refresh where every feed fails leaves an empty set that
    /// blocks nothing. An address feed must never be able to take the machine
    /// off the network, least of all by failing.
    func refreshIPBlocklists() async {
        var feeds = ipFeeds()
        let enabled = feeds.enumerated().filter { $0.element.enabled }
        guard !enabled.isEmpty else {
            applyIPEntries([], to: &feeds)
            return
        }

        var bodies: [Int: IPFeedFetchResult] = [:]
        await withTaskGroup(of: (Int, IPFeedFetchResult).self) { group in
            for (index, feed) in enabled {
                group.addTask { (index, await self.fetchIPFeed(feed)) }
            }
            for await (index, result) in group { bodies[index] = result }
        }

        var entries: [String] = []
        entries.reserveCapacity(IPBlocklistLimits.maxRanges)
        for (index, _) in enabled {
            switch bodies[index] {
            case .some(.body(let text)):
                let parsed = IPBlocklistFeedParser.entries(from: text)
                // Counting happens on the built set, not on the raw lines, so
                // the number the UI shows is the number that can actually
                // match.
                let built = IPBlocklistSet(entries: parsed)
                feeds[index].entryCount = built.acceptedEntryCount
                feeds[index].rejectedCount = built.rejectedEntryCount
                feeds[index].lastUpdated = Date()
                feeds[index].lastError = nil
                let remaining = IPBlocklistLimits.maxRanges - entries.count
                if remaining > 0 {
                    entries.append(contentsOf: built.acceptedEntries.prefix(remaining))
                }
                if built.acceptedEntries.count > remaining {
                    feeds[index].lastError = "combined IP blocklist range limit reached; feed tail was not loaded"
                }
            case .some(.failure(let reason)):
                feeds[index].lastError = reason
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) unavailable: \(reason); it is enforcing nothing")
            case .none:
                feeds[index].lastError = "feed was not read"
                PSLog.error(PSLog.pf, "IP blocklist \(feeds[index].name) was not read; it is enforcing nothing")
            }
        }

        applyIPEntries(entries, to: &feeds)
    }

    /// The current address matcher. Immutable, so a caller can hold it across
    /// a verdict without locking.
    func currentIPBlocklist() -> IPBlocklistSet {
        queue.sync { ipSet }
    }

    /// One immutable value carrying the set, the bypasses that outrank it, and
    /// whether enforcement is on at all.
    func ipBlocklistPolicy(enforcementEnabled: Bool, resolverAddresses: [String] = []) -> IPBlocklistPolicy {
        IPBlocklistPolicy(
            enforcementEnabled: enforcementEnabled,
            blocked: currentIPBlocklist(),
            resolverAddresses: resolverAddresses,
            feeds: ipFeeds()
        )
    }

    private func applyIPEntries(_ entries: [String], to feeds: inout [IPBlocklistFeed]) {
        let set = IPBlocklistSet(entries: entries)
        queue.sync { ipSet = set }
        persistIPFeeds(feeds)
        onIPBlocklistUpdate?(set, feeds)
    }

    private func persistIPFeeds(_ feeds: [IPBlocklistFeed]) {
        queue.sync { ipFeedsCache = feeds }
        guard let data = try? JSONEncoder().encode(feeds),
              let text = String(data: data, encoding: .utf8) else { return }
        try? store.setSetting(BlocklistManager.ipFeedsSettingKey, text)
    }

    private func fetchIPFeed(_ feed: IPBlocklistFeed) async -> IPFeedFetchResult {
        if let ipFeedFetcher { return await ipFeedFetcher(feed) }
        guard let url = URL(string: feed.url), url.scheme == "https" else {
            return .failure("feed URL is not an https URL")
        }
        var request = URLRequest(url: url, timeoutInterval: 30)
        request.setValue("FreeSnitch/0.1", forHTTPHeaderField: "User-Agent")
        do {
            // `data(for:)` waits for and allocates the complete response before
            // this code can inspect its size. AsyncBytes lets us stop at the
            // hard byte ceiling, so a hostile or accidentally huge feed never
            // becomes an unbounded allocation.
            let (bytes, response) = try await URLSession.shared.bytes(for: request)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                return .failure("HTTP \(http.statusCode)")
            }
            var data = Data()
            data.reserveCapacity(min(IPBlocklistLimits.maxFeedBytes, 1 * 1024 * 1024))
            for try await byte in bytes {
                guard data.count < IPBlocklistLimits.maxFeedBytes else {
                    return .failure("feed is larger than the \(IPBlocklistLimits.maxFeedBytes) byte limit")
                }
                data.append(byte)
            }
            guard let text = String(data: data, encoding: .utf8) else {
                return .failure("feed body is not UTF-8")
            }
            return .body(text)
        } catch {
            return .failure("\(error.localizedDescription)")
        }
    }
}
