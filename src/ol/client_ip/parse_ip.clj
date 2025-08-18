;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.parse-ip
  "Parse a string representation of an IPv4 or IPv6 address into an InetAddress instance.

  Unlike `InetAddress/getByName`, the functions in this namespace never cause
  DNS services to be accessed. This avoids potentially blocking/side-effecting
  network calls that can occur when using the JDK's built-in methods to parse IP
  addresses.

  This implementation is inspired by Google Guava's InetAddresses class, which
  provides similar functionality in Java. This code focuses on strict validation
  of IP address formats according to relevant RFCs.

  Features:
  - Non-blocking IP address parsing with pure functions
  - Strict RFC-compliant validation
  - Support for all IPv4 formats
  - Support for all IPv6 formats (including compressed notation and embedded IPv4)
  - Support for IPv6 scope identifiers

  The main entry point is `parse-ip`, which takes a string and returns an
  InetAddress instance or nil if the input is an invalid ip address literal."
  (:require [clojure.string :as str])
  (:import [java.net InetAddress Inet6Address NetworkInterface]))

(def ^:private ipv4-part-count 4)
(def ^:private ipv6-part-count 8)
(def ^:private ipv4-delimiter ".")

(defn- categorize-ip-string
  "Categorizes the characters in an IP string to determine its format.
   Returns a map with {:has-colon :has-dot :percent-index :valid}."
  [^String ip-string]
  (loop [i             0
         has-colon     false
         has-dot       false
         percent-index -1
         valid         true]
    (if (or (not valid) (>= i (count ip-string)))
      {:has-colon     has-colon
       :has-dot       has-dot
       :percent-index percent-index
       :valid         valid}
      (let [c (nth ip-string i)]
        (cond
          (= c \.)                            (recur (inc i) has-colon true percent-index valid)
          (= c \:)                            (recur (inc i) true has-dot percent-index valid)
          (= c \%)                            (recur (inc i) has-colon has-dot i valid)
          (>= percent-index 0)                (recur (inc i) has-colon has-dot percent-index valid) ;; If we've found a percent sign, zone identifiers can contain any character
          (= -1 (Character/digit ^char c 16)) (recur (inc i) has-colon has-dot percent-index false)
          :else                               (recur (inc i) has-colon has-dot percent-index valid))))))

(defn- parse-ipv4-octet
  "Parses an IPv4 octet, rejecting leading zeros, negative values and values > 255."
  [octet-str]
  (let [length (count octet-str)]
    (when (and (pos? length) (<= length 3))
      ;; reject leading zeros to avoid octal interpretation
      (when-not (and (> length 1) (= (first octet-str) \0))
        (try
          (let [value (Integer/parseInt octet-str)]
            (when (<= 0 value 255)
              value))
          (catch NumberFormatException _
            nil))))))

(defn- invalid-ipv4?
  [^String ip-string]
  (or
   ;; reject trailing dots like "1.2.3.4."
   (and (str/ends-with? ip-string ipv4-delimiter)
        (not (= ip-string ipv4-delimiter)))
   ;; reject leading dots
   (str/starts-with? ip-string ipv4-delimiter)
   ;; reject consecutive dots
   (str/includes? ip-string "..")))

(defn- parse-ipv4
  "Parse IPv4 string into byte array.
     Validates:
     - Exactly 4 parts
     - No leading zeros
     - Values 0-255
     - No trailing dots"
  ^bytes [ip-string]
  (when-not (invalid-ipv4? ip-string)
    (let [parts (str/split ip-string #"\.")]
      (when (= (count parts) ipv4-part-count)
        (let [octets (mapv parse-ipv4-octet parts)]
          (when-not (some nil? octets)
            (byte-array (map unchecked-byte octets))))))))

(defn- parse-ipv6-hextet
  "Parse an IPv6 hextet (16-bit segment) or nil if invalid"
  [hextet-str]
  (let [length (count hextet-str)]
    (when (and (pos? length) (<= length 4))
      (try
        (let [value (Integer/parseInt hextet-str 16)]
          (when (<= 0 value 0xFFFF)
            value))
        (catch NumberFormatException _
          nil)))))

(defn- convert-dotted-quad-to-hex
  "Convert an IPv4 dotted-quad part of an IPv6 address to hexadecimal format.
   Example: Given \"::192.168.0.1\", converts \"192.168.0.1\" to \"c0a8:1\""
  [ip-string]
  (when ip-string
    (let [last-colon (str/last-index-of ip-string ":")
          initial-part (subs ip-string 0 (inc last-colon))
          dotted-quad (subs ip-string (inc last-colon))]

      ;; Validate the dotted quad is a valid IPv4 address
      (when-let [quad (parse-ipv4 dotted-quad)]
        (let [penultimate (Integer/toHexString (bit-or
                                                (bit-shift-left (bit-and (int (aget quad 0)) 0xff) 8)
                                                (bit-and (int (aget quad 1)) 0xff)))
              ultimate (Integer/toHexString (bit-or
                                             (bit-shift-left (bit-and (int (aget quad 2)) 0xff) 8)
                                             (bit-and (int (aget quad 3)) 0xff)))]
          (str initial-part penultimate ":" ultimate))))))

(defn- has-too-many-colons?
  "Check if an IPv6 address has more colons than allowed.
  This is in regard to total colons, not consecutive colons."
  [addr-part]
  (when addr-part
    (let [colon-count (count (filter #(= % \:) addr-part))]
      (> colon-count ipv6-part-count))))

(defn- expand-ipv6
  "Expand IPv6 shorthand notation with ::. Returns nil if the format is invalid."
  [^String addr-part]
  (if-not (str/includes? addr-part "::")
    ;; check if we have exactly 8 parts
    (let [parts (str/split addr-part #":")]
      (when (= (count parts) ipv6-part-count)
        addr-part))

    ;; compression with ::
    (let [compression-count (count (re-seq #"::" addr-part))]
      (when (= compression-count 1)     ; Only one :: allowed
        (let [[left right]  (str/split addr-part #"::" 2)
              left-parts    (filter not-empty (str/split left #":"))
              right-parts   (filter not-empty (str/split right #":"))
              total-parts   (+ (count left-parts) (count right-parts))
              missing-parts (- ipv6-part-count total-parts)]

          ;; can :: expand to at least one zero?
          (when (>= missing-parts 1)
            (let [middle-parts (repeat missing-parts "0")]
              (str/join ":" (concat left-parts middle-parts right-parts)))))))))

(defn- invalid-ipv6?
  "Check if an IPv6 address string is invalid due to formatting issues."
  [addr-part]
  (or
   ;; too few or too many colons
   (< (count (filter #(= % \:) addr-part)) 2)
   (has-too-many-colons? addr-part)

   ;; invalid start/end patterns
   (and (not= (count addr-part) 1)
        (str/starts-with? addr-part ":")
        (not (str/starts-with? addr-part "::")))

   (and (not= (count addr-part) 1)
        (str/ends-with? addr-part ":")
        (not (str/ends-with? addr-part "::")))

   (str/includes? addr-part ":::")))

(defn- parse-ipv6
  "Parse IPv6 string into byte array and optional scope ID.
     Performs stricter validation than previous implementation."
  [^String ip-string categorization]
  (let [[addr-part scope-id] (if (>= (:percent-index categorization) 0)
                               [(subs ip-string 0 (:percent-index categorization))
                                (subs ip-string (inc (:percent-index categorization)))]
                               [ip-string nil])]
    (when-not (invalid-ipv6? addr-part)
      (when-let [addr-with-hex (if (and (:has-dot categorization) (:has-colon categorization))
                                 (convert-dotted-quad-to-hex addr-part)
                                 addr-part)]
        (when-let [expanded (expand-ipv6 addr-with-hex)]
          (let [parts         (str/split expanded #":")
                valid-hextets (mapv parse-ipv6-hextet parts)]
            (when (and (= (count parts) ipv6-part-count)
                       (not-any? nil? valid-hextets))
              (let [bytes (byte-array 16)]
                (dotimes [i ipv6-part-count]
                  (let [value (nth valid-hextets i)
                        idx   (* i 2)]
                    (aset bytes idx (unchecked-byte (bit-shift-right value 8)))
                    (aset bytes (inc idx) (unchecked-byte (bit-and value 0xff)))))
                [bytes scope-id]))))))))

(defn- ip-string->bytes
  "Convert an IP string to bytes. Returns [byte-array scope-id] or nil if invalid."
  ^bytes [^String ip-string]
  (when ip-string
    (let [categorization (categorize-ip-string ip-string)]
      (if-not (:valid categorization)
        nil
        (cond
          ;; iPv6 with embedded IPv4
          (and (:has-colon categorization) (:has-dot categorization))
          (parse-ipv6 ip-string categorization)

          ;; normal IPv4
          (:has-dot categorization)
          (when-let [bytes (parse-ipv4 ip-string)]
            [bytes nil])

          ;; normal IPv6
          (:has-colon categorization)
          (parse-ipv6 ip-string categorization)

          :else nil)))))

(defn- try-parse-decimal
  "Attempt to parse a string as a decimal integer."
  [s start end]
  (try
    (Integer/parseInt (subs s start end))
    (catch NumberFormatException _
      -1)))

(defn bytes->inet-address
  "Convert a byte array into an InetAddress.

  Args:
    addr: the raw 4-byte or 16-byte IP address in big-endian order
    scope: optional scope identifier for IPv6 addresses"
  ([addr]
   (bytes->inet-address addr nil))
  ([addr scope]
   (let [address (InetAddress/getByAddress addr)]
     (if scope
       (if (instance? Inet6Address address)
         (let [v6-address      ^Inet6Address address
               interface-index (try-parse-decimal scope 0 (count scope))]
           (if (not= interface-index -1)
             (Inet6Address/getByAddress nil (.getAddress v6-address) ^Integer interface-index)
             (try
               (if-let [as-interface (NetworkInterface/getByName scope)]
                 (Inet6Address/getByAddress nil (.getAddress v6-address) as-interface)
                 (let [host-with-scope (str (.getHostAddress v6-address) "%" scope)]
                   (InetAddress/getByName host-with-scope)))
               ;; network interface resolution is host specific, fallback gradefuly
               (catch Exception _
                 address))))
         address)
       address))))

(defn from-string
  "Returns the InetAddress having the given string representation or nil otherwise.

  This function parses IP address strings without performing DNS lookups, making it
  suitable for environments where DNS lookups would cause unwanted blocking or side effects.

  It supports:
  - IPv4 addresses in dotted decimal format (e.g., \"192.168.1.1\")
  - IPv6 addresses in hex format with optional compression (e.g., \"2001:db8::1\")
  - IPv6 addresses with scope IDs (e.g., \"fe80::1%eth0\" or \"fe80::1%1\")
  - IPv6 addresses with embedded IPv4 (e.g., \"::ffff:192.168.1.1\")

  If the input is already an InetAddress, it is returned unchanged.

  Args:
    ip-string: A string representing an IP address or an InetAddress
               
  Returns:
    An InetAddress object, or nil if the input couldn't be parsed"
  ^InetAddress [ip-string]
  (cond
    (instance? InetAddress ip-string)
    ip-string

    (str/blank? ip-string)
    nil

    :else
    (try
      (when-let [[addr scope] (ip-string->bytes ip-string)]
        (bytes->inet-address addr scope))
      (catch Exception _
        nil))))