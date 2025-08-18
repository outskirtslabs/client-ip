;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.parse-ip-test
  (:require [ol.client-ip.parse-ip :as sut :refer [from-string]]
            [clojure.test :refer [deftest are is testing]])
  (:import [java.net InetAddress Inet6Address]))

(deftest test-parse-ip-valid-ipv4
  (testing "Valid IPv4 addresses"
    (are [ip-str] (= (from-string ip-str)
                     (InetAddress/getByName ip-str))
      "1.2.3.4"
      "192.168.0.1"
      "0.0.0.0"
      "255.255.255.255"
      "10.0.0.1"
      "172.16.0.1"
      "224.0.0.1")))

(deftest test-parse-ip-valid-ipv6
  (testing "Valid IPv6 addresses"
    (are [ip-str] (= (from-string ip-str)
                     (InetAddress/getByName ip-str))
      ;; Standard IPv6
      "1:2:3:4:5:6:7:8"
      "3ffe::1"
      "::"
      "::1"
      "2001:0:0:4:0:0:0:8"
      "2001:0:0:4:5:6:7:8"
      "2001:0:3:4:5:6:7:8"
      "0:0:3:0:0:0:0:ffff"
      "2001:658:22a:cafe::"
      ;; IPv6 with eight colons
      "::7:6:5:4:3:2:1"
      "::7:6:5:4:3:2:0"
      "7:6:5:4:3:2:1::"
      "0:6:5:4:3:2:1::"
      ;; IPv6 with embedded IPv4
      "::1.2.3.4"
      "::ffff:1.2.3.4"
      "7::0.128.0.127"
      "7::0.128.0.128"
      "7::128.128.0.127"
      "7::0.128.128.127")))

(deftest test-parse-ip-with-scope-id
  (testing "IPv6 addresses with scope IDs"
    (testing "Numeric scope IDs"
      (let [address (from-string "fe80::1%1")]
        (is (some? address))
        (is (instance? Inet6Address address))
        (is (.isLinkLocalAddress ^Inet6Address address))
        (is (= 1 (.getScopeId ^Inet6Address address)))))

    (testing "Interface name scopes"
      (let [address (from-string "fe80::1%eth0")]
        (when address
          (is (instance? Inet6Address address))
          (is (.isLinkLocalAddress ^Inet6Address address)))))))

(deftest test-parse-ip-invalid
  (testing "invalid inputs"
    (are [invalid-input] (nil? (from-string invalid-input))
      ""
      "016.016.016.016"
      "016.016.016"
      "016.016"
      "016"
      "000.000.000.000"
      "000"
      "0x0a.0x0a.0x0a.0x0a"
      "0x0a.0x0a.0x0a"
      "0x0a.0x0a"
      "0x0a"
      "42.42.42.42.42"
      "42.42.42"
      "42.42"
      "42"
      "42..42.42"
      "42..42.42.42"
      "42.42.42.42."
      "42.42.42.42..."
      ".42.42.42.42"
      ".42.42.42"
      "...42.42.42.42"
      "42.42.42.-0"
      "42.42.42.+0"
      "."
      "..."
      "bogus"
      "bogus.com"
      "192.168.0.1.com"
      "12345.67899.-54321.-98765"
      "257.0.0.0"
      "42.42.42.-42"
      "42.42.42.ab"
      "3ffe::1.net"
      "3ffe::1::1"
      "1::2::3::4:5"
      "::7:6:5:4:3:2:"       ;; should end     with   ":0"
      ":6:5:4:3:2:1::"       ;; should begin   with   "0:"
      "2001::db:::1"
      "FEDC:9878"
      "+1.+2.+3.4"
      "1.2.3.4e0"
      "6:5:4:3:2:1:0"        ;; too    few     parts
      "::7:6:5:4:3:2:1:0"    ;; too    many    parts
      "7:6:5:4:3:2:1:0::"    ;; too    many    parts
      "9:8:7:6:5:4:3::2:1"   ;; too    many    parts
      "0:1:2:3::4:5:6:7"     ;; ::     must    remove at least one 0.
      "3ffe:0:0:0:0:0:0:0:1" ;; too    many    parts  (9 instead of 8)
      "3ffe::10000"          ;; hextet exceeds 16     bits
      "3ffe::goog"
      "3ffe::-0"
      "3ffe::+0"
      "3ffe::-1"
      ":"
      ":::"
      "::1.2.3"
      "::1.2.3.4.5"
      "::1.2.3.4:"
      "1.2.3.4::"
      "2001:db8::1:"
      ":2001:db8::1"
      ":1:2:3:4:5:6:7"
      "1:2:3:4:5:6:7:"
      ":1:2:3:4:5:6:")))