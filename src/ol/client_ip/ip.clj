(ns ol.client-ip.ip
  "IP address utilities for conversion and classification.

  This namespace provides functions for working with IP addresses,
  particularly for converting between string, InetAddress, and numeric
  representations. It follows RFC 5952 for IPv6 address formatting and
  provides utilities for type checking and serialization.

  NOTE: None of the functions in this namespace accept ip addreses input as strings.
  Use [[ol.client-ip.parse-ip/from-string]] to convert strings to InetAddress objects.

  The key operations available are:

  * Type checking with `ipv4?` and `ipv6?`
  * String formatting with `format-ip`
  * Numeric conversion with `->numeric` and `numeric->`

  These functions are designed to work with the `java.net.InetAddress`
  class hierarchy and its subclasses `Inet4Address` and `Inet6Address`.

  Refer to [[ol.client-ip.parse-ip]] and [[ol.client-ip.cidr]] for more useful functions.
  "
  (:import [java.net InetAddress Inet4Address Inet6Address UnknownHostException]
           [java.math BigInteger]))

(defn ipv4?
  "Checks if an IP address is an IPv4 address.
  
  This function determines if the given IP address is an instance of
  `java.net.Inet4Address`.
  
  Arguments:
    ip - An IP address object (InetAddress)
  
  Returns:
    `true` if the IP address is IPv4, `false` otherwise
  
  Examples:
  ```clojure
  (ipv4? (parse-ip/from-string \"192.168.1.1\")) ;; => true
  (ipv4? (parse-ip/from-string \"::1\"))         ;; => false
  ```"
  [ip]
  (instance? Inet4Address ip))

(defn ipv6?
  "Checks if an IP address is an IPv6 address.
  
  This function determines if the given IP address is an instance of
  `java.net.Inet6Address`.
  
  Arguments:
    ip - An IP address object (InetAddress)
  
  Returns:
    `true` if the IP address is IPv6, `false` otherwise
  
  Examples:
  ```clojure
  (ipv6? (parse-ip/from-string \"2001:db8::1\")) ;; => true
  (ipv6? (parse-ip/from-string \"192.168.1.1\")) ;; => false
  ```"
  [ip]
  (instance? Inet6Address ip))

(defn- scope-with-delimiter [^Inet6Address ip]
  (let [scoped-interface (.getScopedInterface ip)]
    (cond
      (some? scoped-interface)  (str "%" (.getName scoped-interface))
      (not= 0 (.getScopeId ip)) (str "%" (.getScopeId ip))
      :else                     "")))

(defn- hextets-to-ipv6-string [hextets]
  (loop [i               0
         last-was-number false
         result          ""]
    (if (< i (count hextets))
      (let [this-is-number (>= (nth hextets i) 0)]
        (cond
          this-is-number
          (recur (inc i)
                 true
                 (str result
                      (when last-was-number ":")
                      (Integer/toHexString (nth hextets i))))
          (or (zero? i) last-was-number)
          (recur (inc i)
                 false
                 (str result "::"))
          :else
          (recur (inc i) false result)))
      result)))

(defn- find-longest-zero-run [hextets]
  (loop [i              0
         current-start  -1
         current-length 0
         best-start     -1
         best-length    0]
    (if (< i (count hextets))
      (if (zero? (nth hextets i))
        (let [start  (if (= current-start -1) i current-start)
              length (inc current-length)]
          (recur (inc i) start length
                 (if (> length best-length) start best-start)
                 (if (> length best-length) length best-length)))
        (recur (inc i) -1 0 best-start best-length))
      [best-start best-length])))

(defn- compress-longest-run-of-zeroes [hextets]
  (let [[best-start best-length] (find-longest-zero-run hextets)]
    (if (> best-length 1)
      (vec (concat
            (take best-start hextets)
            (repeat best-length -1)
            (drop (+ best-start best-length) hextets)))
      hextets)))

(defn format-ipv6
  "Converts an IPv6 address to its canonical string representation.
  
  This function formats IPv6 addresses according to RFC 5952, which includes:
  - Using lowercase hexadecimal digits
  - Compressing the longest run of consecutive zero fields with ::
  - Not using :: to compress a single zero field
  - Including scope IDs with % delimiter for link-local addresses
  
  Arguments:
    ip - An IPv6 address object (Inet6Address)
  
  Returns:
    A string representation of the IPv6 address formatted according to RFC 5952
    
  Examples:
  ```clojure
  (format-ipv6 (parse-ip/from-string \"2001:db8:0:0:0:0:0:1\"))
  ;; => \"2001:db8::1\"
  
  (format-ipv6 (parse-ip/from-string \"fe80::1%eth0\"))
  ;; => \"fe80::1%eth0\"
  ```"
  [^Inet6Address ip]
  (let [bytes      (.getAddress ip)
        hextets    (vec (for [i (range 8)]
                          (bit-or
                           (bit-shift-left (bit-and (int (aget bytes (* 2 i))) 0xff) 8)
                           (bit-and (int (aget bytes (+ (* 2 i) 1))) 0xff))))
        compressed (compress-longest-run-of-zeroes hextets)]
    (str (hextets-to-ipv6-string compressed)
         (scope-with-delimiter ip))))

(defn format-ip
  "Converts an IP address to its canonical string representation.

  This function formats IP addresses according to standard conventions:
  - IPv4 addresses use dotted decimal notation (e.g., \"192.168.0.1\")
  - IPv6 addresses follow RFC 5952 with compressed notation using ::
    for the longest run of zeros, and embedded IPv4 addresses where appropriate

  The implementation handles scope IDs for IPv6 link-local addresses
  and properly compresses IPv6 addresses according to the standard rules.

  Arguments:
    ip - An IP address object (InetAddress)

  Returns:
    A string representation of the IP address
    
  Throws:
    IllegalArgumentException - if the input is not a valid InetAddress

  Examples:
  ```clojure
  (format-ip (parse-ip/from-string \"192.168.1.1\"))   ;; => \"192.168.1.1\"
  (format-ip (parse-ip/from-string \"2001:db8::1\"))   ;; => \"2001:db8::1\"
  (format-ip (parse-ip/from-string \"::ffff:1.2.3.4\")) ;; => \"::ffff:1.2.3.4\"
  ```"
  [ip]
  (cond
    (ipv4? ip)
    (.getHostAddress ^Inet4Address ip)
    (ipv6? ip)
    (format-ipv6 ^Inet6Address ip)))

(defn ->numeric
  "Converts an IP address to its numeric representation as a BigInteger.

  This function takes an InetAddress (either IPv4 or IPv6) and returns
  a BigInteger representing the address. The BigInteger can be used for
  IP address arithmetic, comparison, or storage.

  Arguments:
    ip - An IP address object (InetAddress)

  Returns:
    A BigInteger representing the IP address
    
  Examples:
  ```clojure
  (->numeric (parse-ip/from-string \"192.0.2.1\"))
  ;; => 3221225985

  (->numeric (parse-ip/from-string \"2001:db8::1\"))
  ;; => 42540766411282592856903984951653826561
  ```"
  ^BigInteger [^InetAddress ip]
  (BigInteger. 1 (.getAddress ip)))

(defn numeric->
  "Converts a BigInteger to an InetAddress.

  This function takes a numeric representation of an IP address as a BigInteger
  and converts it back to an InetAddress object. The `ipv6?` flag determines
  whether to create an IPv4 or IPv6 address.

  Arguments:
    address - A BigInteger representing the IP address
    version - One of :v6 or :v4 indicating whether this is an IPv6 address
              or an IPv4 address

  Returns:
    An InetAddress object representing the numeric address, or nil 
    
  Throws:
    ExceptionInfo - If the BigInteger is negative or too large for the
                   specified address type
    
  Examples:
  ```clojure
  ;; Convert back to IPv4
  (numeric-> (BigInteger. \"3221226113\") :v4)
  ;; => #object[java.net.Inet4Address 0x578d1c5 \"/192.0.2.129\"]

  ;; Convert back to IPv6
  (numeric-> (BigInteger. \"42540766411282592856903984951653826561\") :v6)
  ;; => #object[java.net.Inet6Address 0x14832c23 \"/2001:db8:0:0:0:0:0:1\"]
  ```"
  [^BigInteger address version]
  (when-not (>= (.signum address) 0)
    (throw (ex-info "BigInteger must be greater than or equal to 0"
                    {:type :invalid-big-integer :address address})))
  (let [num-bytes     (condp = version
                        :v6 16
                        :v4 4)
        address-bytes (.toByteArray address)
        target-array  (byte-array num-bytes)
        src-pos       (max 0 (- (alength address-bytes) num-bytes))
        copy-length   (- (alength address-bytes) src-pos)
        dest-pos      (- num-bytes copy-length)]
    (loop [i 0]
      (when (< i src-pos)
        (when-not (zero? (aget address-bytes i))
          (throw (ex-info
                  (format "BigInteger cannot be converted to InetAddress because it has more than %d bytes: %s"
                          num-bytes address)
                  {:type :big-integer-too-large :big-integer address :max-bytes num-bytes})))
        (recur (inc i))))
    (System/arraycopy address-bytes src-pos target-array dest-pos copy-length)
    (try
      (InetAddress/getByAddress target-array)
      (catch UnknownHostException e
        (throw (ex-info "Failed to create InetAddress from byte array"
                        {:type         :invalid-address-bytes
                         :target-array target-array
                         :cause        e}))))))

(defn numeric-v6->
  "Converts a BigInteger to an IPv6 address.

  This is a convenience wrapper around `numeric->` that automatically
  sets the `ipv6?` flag to true.

  Arguments:
    address - A BigInteger representing the IPv6 address

  Returns:
    An Inet6Address object or nil if the input is invalid
    
  See also: [[numeric->]]

  Examples:
  ```clojure
  (numeric-v6-> (BigInteger. \"42540766411282592856903984951653826561\"))
  ;; => #object[java.net.Inet6Address 0x42668812 \"/2001:db8:0:0:0:0:0:1\"]
  ```"
  [^BigInteger address]
  (try
    (numeric-> address :v6)
    (catch Exception _
      nil)))

(defn numeric-v4->
  "Converts a BigInteger to an IPv4 address.

  Arguments:
    address - A BigInteger representing the IPv4 address

  Returns:
    An Inet4Address object or nil if the input is invalid
    
  See also: [[numeric->]]

  Examples:
  ```clojure
  (numeric-v4-> (BigInteger. \"3221226113\"))
  ;; => #object[java.net.Inet4Address 0x6b88aeff \"/192.0.2.129\"]
```"
  [^BigInteger address]
  (try
    (numeric-> address :v4)
    (catch Exception _
      nil)))
