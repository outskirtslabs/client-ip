(ns ol.client-ip.cidr
  (:refer-clojure :exclude [contains?])
  (:require [clojure.string :as str]
            [ol.client-ip.ip :as ip]
            [ol.client-ip.parse-ip :as parse-ip])
  (:import [java.net InetAddress]))

(defn- get-network-address [ip subnet]
  (reduce
   (fn [^BigInteger n bit] (.clearBit n bit))
   (ip/->numeric ip)
   (if (ip/ipv4? ip)
     (range (clojure.core/- 32 subnet))
     (range (clojure.core/- 128 subnet)))))

(defn- get-broadcast-address [ip subnet]
  (reduce
   (fn [^BigInteger n bit] (.setBit n bit))
   (ip/->numeric ip)
   (if (ip/ipv4? ip)
     (range (clojure.core/- 32 subnet))
     (range (clojure.core/- 128 subnet)))))

(defn cidr-parts
  "Parse an ip network string into its prefix and signifcant bits

  `cidr` must be given in CIDR notation, as defined in [RFC 4632 section 3.1](https://tools.ietf.org/html/rfc4632#section-3.1)

  Returns a vector of [^InetAddress prefix ^Integer bits]"
  [^String cidr]
  (try
    (if (str/includes? cidr "/")
      (let [[ip mask] (str/split cidr #"/")]
        [(parse-ip/from-string ip) (Integer/parseInt mask)])
      [(parse-ip/from-string cidr) (int -1)])
    (catch Exception _
      nil)))

(defn contains?
  "Check if the given CIDR contains the given IP address.
   
   Arguments:
     cidr - CIDR notation string (e.g. \"192.168.0.0/24\" or \"2001:db8::/32\")
     ip   - IP address to check (can be InetAddress or string)"
  ([^String cidr ip]
   (let [[cidr-ip cidr-mask] (cidr-parts cidr)]
     (contains? cidr-ip cidr-mask  ip)))
  ([^InetAddress cidr-ip ^Integer cidr-mask ip]
   (try
     (let [ip-addr (if (string? ip) (parse-ip/from-string ip) ip)]
       (if (and cidr-ip ip-addr)
         (let [query-address (ip/->numeric ip-addr)
               max-address   (get-broadcast-address cidr-ip cidr-mask)
               min-address   (get-network-address cidr-ip cidr-mask)]
           (and (>= (.compareTo query-address min-address) 0)
                (<= (.compareTo query-address max-address) 0)))
         false))
     (catch Exception _
       false))))

;; privateAndLocalRanges that are loopback, private, link local, default unicast.
;; Based on https://github.com/wader/filtertransport/blob/bdd9e61eee7804e94ceb927c896b59920345c6e4/filter.go#L36-L64
;; which is based on https://github.com/letsencrypt/boulder/blob/master/bdns/dns.go
(def reserved-ranges
  (mapv cidr-parts  ["10.0.0.0/8"         ;; RFC1918
                     "172.16.0.0/12"      ;; private
                     "192.168.0.0/16"     ;; private
                     "127.0.0.0/8"        ;; RFC5735
                     "0.0.0.0/8"          ;; RFC1122 Section 3.2.1.3
                     "169.254.0.0/16"     ;; RFC3927
                     "192.0.0.0/24"       ;; RFC 5736
                     "192.0.2.0/24"       ;; RFC 5737
                     "198.51.100.0/24"    ;; Assigned as TEST-NET-2
                     "203.0.113.0/24"     ;; Assigned as TEST-NET-3
                     "192.88.99.0/24"     ;; RFC 3068
                     "192.18.0.0/15"      ;; RFC 2544
                     "224.0.0.0/4"        ;; RFC 3171
                     "240.0.0.0/4"        ;; RFC 1112
                     "255.255.255.255/32" ;; RFC 919 Section 7
                     "100.64.0.0/10"      ;; RFC 6598
                     "::/128"             ;; RFC 4291: Unspecified Address
                     "::1/128"            ;; RFC 4291: Loopback Address
                     "100::/64"           ;; RFC 6666: Discard Address Block
                     "2001::/23"          ;; RFC 2928: IETF Protocol Assignments
                     "2001:2::/48"        ;; RFC 5180: Benchmarking
                     "2001:db8::/32"      ;; RFC 3849: Documentation
                     "2001::/32"          ;; RFC 4380: TEREDO
                     "fc00::/7"           ;; RFC 4193: Unique-Local
                     "fe80::/10"          ;; RFC 4291: Section 2.5.6 Link-Scoped Unicast
                     "ff00::/8"           ;; RFC 4291: Section 2.7
                     "2002::/16"]))       ;; RFC 7526: 6to4 anycast prefix deprecated

(defn reserved?
  "Check if an IP is in a reserved range (loopback or private network)."
  [ip]
  (boolean (some (fn [[c-ip c-mask]] (contains? c-ip c-mask ip)) reserved-ranges)))
