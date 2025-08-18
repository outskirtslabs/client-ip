;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.strategy
  "Strategy implementations for determining client IP addresses.

  This namespace provides various strategy implementations for extracting the
  real client IP from HTTP headers and connection information.

  Each strategy is designed for specific network configurations:

  * `RemoteAddrStrategy` - Direct connections (no reverse proxy)
  * `SingleIPHeaderStrategy` - Single trusted reverse proxy with single IP headers
  * `RightmostNonPrivateStrategy` - Multiple proxies, all with private IPs
  * `LeftmostNonPrivateStrategy` - Get IP closest to original client (not secure)
  * `RightmostTrustedCountStrategy` - Fixed number of trusted proxies
  * `RightmostTrustedRangeStrategy` - Known trusted proxy IP ranges
  * `ChainStrategy` - Try multiple strategies in order

  Strategies are created once and reused across requests. They are thread-safe
  and designed to fail fast on configuration errors while being resilient to
  malformed input during request processing."
  (:require [clojure.string :as str]
            [ol.client-ip.parse-ip :as parse-ip]
            [ol.client-ip.cidr :as cidr]
            [ol.client-ip.protocols :refer [ClientIPStrategy client-ip]]))

(def ^:private zero-ipv4 (parse-ip/from-string "0.0.0.0"))
(def ^:private zero-ipv6 (parse-ip/from-string "::"))

(defn- zero-or-unspecified?
  "Check if an IP address is zero (0.0.0.0) or unspecified (::).
  These are valid IPs technically but should be treated as invalid in headers."
  [ip-address]
  (when ip-address
    (or (.equals ^java.net.InetAddress ip-address zero-ipv4)
        (.equals ^java.net.InetAddress ip-address zero-ipv6))))

(defn- strip-port
  "Strip port from IP:port string, returning just the IP.
  Handles both IPv4:port and [IPv6]:port formats."
  [ip-string]
  (cond
    ;; IPv6 with port: [IPv6]:port -> IPv6
    (re-matches #"\[.*\]:[0-9]+" ip-string)
    (let [closing-bracket (str/last-index-of ip-string "]")]
      (subs ip-string 1 closing-bracket))

    ;; IPv6 without port but with brackets: [IPv6] -> IPv6
    (and (str/starts-with? ip-string "[") (str/ends-with? ip-string "]"))
    (subs ip-string 1 (dec (count ip-string)))

    ;; IPv4 with port: IPv4:port -> IPv4
    (re-matches #"[0-9.]+:[0-9]+" ip-string)
    (first (str/split ip-string #":"))

    ;; No port or other format
    :else ip-string))

(defn- parse-single-ip
  "Parse a single IP from a header value.
  Used for headers like X-Real-IP that contain only one IP address."
  [header-value]
  (when (and header-value (not (str/blank? header-value)))
    (let [ip-string (-> header-value str/trim strip-port)]
      (when-let [ip (parse-ip/from-string ip-string)]
        (when-not (zero-or-unspecified? ip)
          ip)))))

(defn- parse-comma-separated
  "Parse comma-separated IP addresses from header value.
  Used for headers like X-Forwarded-For. Returns vector of valid IP strings."
  [header-value]
  (if (and header-value (not (str/blank? header-value)))
    (->> (str/split (str/trim header-value) #"\s*,\s*")
         (map str/trim)
         (map strip-port)
         (keep (fn [ip-string]
                 (when-let [ip (parse-ip/from-string ip-string)]
                   (when-not (zero-or-unspecified? ip)
                     ip))))
         (vec))
    []))

(defn- extract-forwarded-for
  "Extract 'for' values from a Forwarded header segment.
   Returns a sequence of potential IP strings."
  [segment]
  (let [segment (str/trim segment)]
    (->> (re-seq #"(?i)for\s*=\s*(?:\"([^\"]+)\"|([^;,\s]+))" segment)
         (map (fn [[_ quoted unquoted]]
                (let [value (or quoted unquoted)]
                  (when (and value
                             (not (str/starts-with? value "_"))
                             (not= "unknown" (str/lower-case value)))
                    value))))
         (filter some?)
         (vec))))

(defn- clean-ipv6-brackets
  "Remove surrounding brackets from IPv6 addresses if present and extract port if available.
   Returns the IP address string without brackets, discarding any port information."
  [ip-str]
  (cond
    ;; IPv6 address with port: "[IPv6]:port" -> extract IPv6 address only
    (re-matches #"\[.*\]:[0-9]+" ip-str)
    (let [closing-bracket-idx (str/last-index-of ip-str "]")]
      (subs ip-str 1 closing-bracket-idx))

    ;; IPv6 address without port: "[IPv6]" -> remove brackets
    (and (str/starts-with? ip-str "[") (str/ends-with? ip-str "]"))
    (subs ip-str 1 (dec (count ip-str)))

    ;; IPv4 address with port: "IPv4:port" -> extract IPv4 address only
    (re-matches #"[0-9.]+:[0-9]+" ip-str)
    (first (str/split ip-str #":"))

    :else ip-str))

(defn parse-forwarded
  "Parse a Forwarded header value according to RFC 7239.
   Returns a sequence of InetAddress objects, or an empty sequence if none are valid."
  [header-value]
  (if header-value
    (let [segments (str/split (str/trim header-value) #"\s*,\s*")]
      (->> segments
           (mapcat extract-forwarded-for)
           (map clean-ipv6-brackets)
           (keep parse-ip/from-string)
           (vec)))
    []))

(defn- parse-forwarded-ips
  "Parse IPs from RFC 7239 Forwarded header value.
   Returns vector of valid IP strings."
  [header-value]
  (if (and header-value (not (str/blank? header-value)))
    (->> (parse-forwarded header-value)
         (remove #(zero-or-unspecified? %))
         (vec))
    []))

(defn- parse-multi-ip-header
  "Parse IPs from header value, auto-detecting format.
  Uses RFC 7239 parsing for 'forwarded' header, comma-separated for others."
  [header-name header-value]
  (if (= "forwarded" header-name)
    (parse-forwarded-ips header-value)
    (parse-comma-separated header-value)))

(defn split-host-zone
  "Split IPv6 zone from IP address. 

  IPv6 addresses can include zone identifiers (scope IDs) separated by '%'.
  For example: 'fe80::1%eth0' or 'fe80::1%1'

  Args:
    ip-string: String IP address that may contain a zone identifier
    
  Returns:
    Vector of [ip zone] where zone is the zone identifier string, 
    or [ip nil] if no zone is present.
    
  Examples:
    (split-host-zone \"192.168.1.1\") => [\"192.168.1.1\" nil]
    (split-host-zone \"fe80::1%eth0\") => [\"fe80::1\" \"eth0\"]
    (split-host-zone \"fe80::1%1\") => [\"fe80::1\" \"1\"]"
  [ip-string]
  (if (and ip-string (str/includes? ip-string "%"))
    (let [parts (str/split ip-string #"%" 2)]
      [(first parts) (second parts)])
    [ip-string nil]))

;; Strategy Implementations

(deftype RemoteAddrStrategy []
  ClientIPStrategy
  (client-ip [_ _ remote-addr]
    (when (and remote-addr (not (str/blank? remote-addr)))
      (let [ip-string (strip-port (str/trim remote-addr))]
        (when-let [ip (parse-ip/from-string ip-string)]
          (when-not (zero-or-unspecified? ip)
            ip))))))

(defn remote-addr-strategy
  "Create a strategy that uses the direct client socket IP.

  This strategy extracts the IP address from the request's :remote-addr field,
  which represents the direct client socket connection. Use this when your
  server accepts direct connections from clients (not behind a reverse proxy).

  The strategy strips any port information and validates the IP is not
  zero/unspecified (0.0.0.0 or ::).

  Returns:
    RemoteAddrStrategy instance
    
  Example:
    (remote-addr-strategy)"
  []
  (->RemoteAddrStrategy))

(deftype SingleIPHeaderStrategy [header-name]
  ClientIPStrategy
  (client-ip [_ headers _]
    (when-let [header-value (get headers header-name)]
      (parse-single-ip header-value))))

(defn single-ip-header-strategy
  "Create a strategy that extracts IP from headers containing a single IP address.

  This strategy is designed for headers like X-Real-IP, CF-Connecting-IP,
  True-Client-IP, etc. that contain only one IP address. Use this when you
  have a single trusted reverse proxy that sets a reliable single-IP header.

  The strategy validates that the header name is not X-Forwarded-For or
  Forwarded, as these headers can contain multiple IPs and should use
  different strategies.

  Args:
    header-name: String name of the header to check (case-insensitive)
    
  Returns:
    SingleIPHeaderStrategy instance
    
  Throws:
    ExceptionInfo if header-name is invalid or refers to multi-IP headers
    
  Examples:
    (single-ip-header-strategy \"x-real-ip\")
    (single-ip-header-strategy \"cf-connecting-ip\")"
  [header-name]
  (when (str/blank? header-name)
    (throw (ex-info "Header name cannot be blank" {:header-name header-name})))

  (->SingleIPHeaderStrategy header-name))

(deftype RightmostNonPrivateStrategy [header-name]
  ClientIPStrategy
  (client-ip [_ headers _]
    (when-let [header-value (get headers header-name)]
      (let [ips (parse-multi-ip-header header-name header-value)]
        (loop [remaining (reverse ips)]
          (when-let [ip-string (first remaining)]
            (if-let [ip (parse-ip/from-string ip-string)]
              (if (cidr/reserved? ip)
                (recur (rest remaining))
                ip)
              (recur (rest remaining)))))))))

(defn rightmost-non-private-strategy
  "Create a strategy that gets the rightmost non-private IP from forwarding headers.
  
  This strategy processes IPs in reverse order (rightmost first) and returns
  the first IP that is not in a private/reserved range. Use this when all
  your reverse proxies have private IP addresses, so the rightmost non-private
  IP should be the real client IP.
  
  The strategy supports X-Forwarded-For and Forwarded headers that contain
  comma-separated IP lists.
  
  Args:
    header-name: String name of the header to check (case-insensitive)
                Should be \"x-forwarded-for\" or \"forwarded\"
    
  Returns:
    RightmostNonPrivateStrategy instance
    
  Throws:
    ExceptionInfo if header-name is invalid or refers to single-IP headers
    
  Examples:
    (rightmost-non-private-strategy \"x-forwarded-for\")
    (rightmost-non-private-strategy \"forwarded\")"
  [header-name]
  (when (str/blank? header-name)
    (throw (ex-info "Header name cannot be blank" {:header-name header-name})))

  (->RightmostNonPrivateStrategy header-name))

(deftype LeftmostNonPrivateStrategy [header-name]
  ClientIPStrategy
  (client-ip [_ headers _]
    (when-let [header-value (get headers header-name)]
      (let [ips (parse-multi-ip-header header-name header-value)]
        (loop [remaining ips]
          (when-let [ip-string (first remaining)]
            (if-let [ip (parse-ip/from-string ip-string)]
              (if (cidr/reserved? ip)
                (recur (rest remaining))
                ip)
              (recur (rest remaining)))))))))

(defn leftmost-non-private-strategy
  "Create a strategy that gets the leftmost non-private IP from forwarding headers.
  
  This strategy processes IPs in forward order (leftmost first) and returns
  the first IP that is not in a private/reserved range. This gets the IP
  closest to the original client.
  
  ⚠️  **WARNING: NOT FOR SECURITY USE** ⚠️
  This strategy is easily spoofable since clients can add arbitrary IPs to
  the beginning of forwarding headers. Use only when security is not a concern
  and you want the IP closest to the original client.
  
  The strategy supports X-Forwarded-For and Forwarded headers that contain
  comma-separated IP lists.
  
  Args:
    header-name: String name of the header to check (case-insensitive)
                Should be \"x-forwarded-for\" or \"forwarded\"
    
  Returns:
    LeftmostNonPrivateStrategy instance
    
  Throws:
    ExceptionInfo if header-name is invalid or refers to single-IP headers
    
  Examples:
    (leftmost-non-private-strategy \"x-forwarded-for\")
    (leftmost-non-private-strategy \"forwarded\")"
  [header-name]
  (when (str/blank? header-name)
    (throw (ex-info "Header name cannot be blank" {:header-name header-name})))

  (->LeftmostNonPrivateStrategy header-name))

(deftype RightmostTrustedCountStrategy [header-name trusted-count]
  ClientIPStrategy
  (client-ip [_ headers _]
    (when-let [header-value (get headers header-name)]
      (let [ips (parse-multi-ip-header header-name header-value)
            total-count (count ips)]
        (when (> total-count trusted-count)
          (let [target-index (- total-count trusted-count 1)]
            (when (>= target-index 0)
              (nth ips target-index nil))))))))

(defn rightmost-trusted-count-strategy
  "Create a strategy that returns IP at specific position based on known proxy count.
  
  This strategy is for when you have a fixed number of trusted proxies and want
  to get the IP at the specific position that represents the original client.
  Given N trusted proxies, the client IP should be at position -(N+1) from the end.
  
  For example, with 2 trusted proxies and header 'client, proxy1, proxy2, proxy3':
  - Total IPs: 4
  - Skip last 2 (trusted): positions 2,3 
  - Return IP at position 1 (proxy1)
  
  Args:
    header-name: String name of the header to check (case-insensitive)
                Should be \"x-forwarded-for\" or \"forwarded\"
    trusted-count: Number of trusted proxies (must be > 0)
    
  Returns:
    RightmostTrustedCountStrategy instance
    
  Throws:
    ExceptionInfo if header-name is invalid or trusted-count <= 0
    
  Examples:
    (rightmost-trusted-count-strategy \"x-forwarded-for\" 1)
    (rightmost-trusted-count-strategy \"forwarded\" 2)"
  [header-name trusted-count]
  (when (str/blank? header-name)
    (throw (ex-info "Header name cannot be blank" {:header-name header-name})))

  (when (<= trusted-count 0)
    (throw (ex-info "Trusted count must be positive" {:trusted-count trusted-count})))

  (->RightmostTrustedCountStrategy header-name trusted-count))

(deftype RightmostTrustedRangeStrategy [header-name trusted-ranges]
  ClientIPStrategy
  (client-ip [_ headers _]
    (when-let [header-value (get headers header-name)]
      (let [ips (parse-multi-ip-header header-name header-value)]
        (loop [remaining (reverse ips)]
          (when-let [ip-string (first remaining)]
            (if-let [ip (parse-ip/from-string ip-string)]
              (if (some #(cidr/contains? % ip) trusted-ranges)
                (recur (rest remaining))
                ip)
              (recur (rest remaining)))))))))

(defn rightmost-trusted-range-strategy
  "Create a strategy that returns rightmost IP not in trusted ranges.

  This strategy processes IPs in reverse order (rightmost first) and returns
  the first IP that is not within any of the specified trusted IP ranges.
  Use this when you know the specific IP ranges of your trusted proxies.

  The strategy supports X-Forwarded-For and Forwarded headers that contain
  comma-separated IP lists.

  Args:
    header-name: String name of the header to check (case-insensitive)
                Should be \"x-forwarded-for\" or \"forwarded\"
    trusted-ranges: Collection of CIDR ranges (strings) that represent trusted proxies
                   Each range should be a valid CIDR notation like \"192.168.1.0/24\"
    
  Returns:
    RightmostTrustedRangeStrategy instance
    
  Throws:
    ExceptionInfo if header-name is invalid or trusted-ranges is empty/invalid
    
  Examples:
    (rightmost-trusted-range-strategy \"x-forwarded-for\" [\"10.0.0.0/8\" \"192.168.0.0/16\"])
    (rightmost-trusted-range-strategy \"forwarded\" [\"172.16.0.0/12\"])"
  [header-name trusted-ranges]
  (when (str/blank? header-name)
    (throw (ex-info "Header name cannot be blank" {:header-name header-name})))

  (when (or (nil? trusted-ranges) (empty? trusted-ranges))
    (throw (ex-info "Trusted ranges cannot be empty" {:trusted-ranges trusted-ranges})))

  (let [validated-ranges (mapv (fn [range-str]
                                 (let [[ip mask] (cidr/cidr-parts range-str)]
                                   (when (or (nil? ip) (< mask 0))
                                     (throw (ex-info "Invalid CIDR range" {:range range-str})))
                                   range-str))
                               trusted-ranges)]
    (->RightmostTrustedRangeStrategy header-name validated-ranges)))

(deftype ChainStrategy [strategies]
  ClientIPStrategy
  (client-ip [_ headers remote-addr]
    (loop [remaining strategies]
      (when-let [strategy (first remaining)]
        (if-let [result (client-ip strategy headers remote-addr)]
          result
          (recur (rest remaining)))))))

(defn chain-strategy
  "Create a strategy that tries multiple strategies in order until one succeeds.

  This strategy allows fallback scenarios where you want to try different
  IP detection methods in priority order. Each strategy is tried in sequence
  until one returns a non-empty result.

  Common use case: Try a single-IP header first, then fall back to remote address.

  Args:
    strategies: Vector of strategy instances to try in order
               Must contain at least one strategy
    
  Returns:
    ChainStrategy instance
    
  Throws:
    ExceptionInfo if strategies is empty or contains invalid strategies
    
  Examples:
    (chain-strategy [(single-ip-header-strategy \"x-real-ip\")
                     (remote-addr-strategy)])
    (chain-strategy [(rightmost-non-private-strategy \"x-forwarded-for\")
                     (single-ip-header-strategy \"x-real-ip\")
                     (remote-addr-strategy)])"
  [strategies]
  (when (or (nil? strategies) (empty? strategies))
    (throw (ex-info "Strategies cannot be empty" {:strategies strategies})))

  (doseq [strategy strategies]
    (when-not (satisfies? ClientIPStrategy strategy)
      (throw (ex-info "All items must be ClientIPStrategy instances"
                      {:invalid-strategy strategy
                       :type             (type strategy)}))))

  (->ChainStrategy (vec strategies)))