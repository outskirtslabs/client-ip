;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.ip-test
  (:require [ol.client-ip.ip :as sut :refer [format-ip ipv4? ipv6? ->numeric numeric->]]
            [ol.client-ip.parse-ip :as parse-ip]
            [clojure.test :refer [deftest are is testing]]))

(defn parse-ip [ip-str]
  (parse-ip/from-string ip-str))

(deftest test-ipv4
  (are [expected input] (= expected (ipv4? (parse-ip input)))
    false "1:2:3:4:5:6:7:8"
    true  "1.2.3.4"))

(deftest test-ipv6?
  (are [expected input] (= expected (ipv6? (parse-ip input)))
    true  "1:2:3:4:5:6:7:8"
    true "::1.2.3.4"
    true  "::"
    false "1.2.3.4"))

(deftest format-ipv4
  (is (= "1.2.3.4" (format-ip (parse-ip "1.2.3.4")))))

(deftest format-ipv6
  (are [expected input] (= expected (format-ip (parse-ip input)))
    "1:2:3:4:5:6:7:8"     "1:2:3:4:5:6:7:8"
    "2001:0:0:4::8"       "2001:0:0:4:0:0:0:8"
    "2001::4:5:6:7:8"     "2001:0:0:4:5:6:7:8"
    "2001:0:3:4:5:6:7:8"  "2001:0:3:4:5:6:7:8"
    "0:0:3::ffff"         "0:0:3:0:0:0:0:ffff"
    "::4:0:0:0:ffff"      "0:0:0:4:0:0:0:ffff"
    "::5:0:0:ffff"        "0:0:0:0:5:0:0:ffff"
    "1::4:0:0:7:8"        "1:0:0:4:0:0:7:8"
    "::"                  "0:0:0:0:0:0:0:0"
    "::1"                 "0:0:0:0:0:0:0:1"
    "2001:658:22a:cafe::" "2001:0658:022a:cafe::"
    "::102:304"           "::1.2.3.4"))

(defn round-trip-numeric-conversion [ip-str expected-big-int]
  (let [address (parse-ip ip-str)
        ipv6?   (ipv6? address)]
    (is (= expected-big-int (->numeric address)))
    (is (= address (numeric-> expected-big-int (if ipv6? :v6 :v4))))))

(deftest test-from-ipv6-big-integer-valid
  (testing "IPv6 address to/from BigInteger conversion"
    (round-trip-numeric-conversion "::" BigInteger/ZERO)
    (round-trip-numeric-conversion "::1" BigInteger/ONE)
    (round-trip-numeric-conversion
     "::7fff:ffff"
     (BigInteger/valueOf Integer/MAX_VALUE))
    (round-trip-numeric-conversion
     "::7fff:ffff:ffff:ffff"
     (BigInteger/valueOf Long/MAX_VALUE))
    (round-trip-numeric-conversion
     "::ffff:ffff:ffff:ffff"
     (.subtract (.shiftLeft BigInteger/ONE 64) BigInteger/ONE))
    (round-trip-numeric-conversion
     "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
     (.subtract (.shiftLeft BigInteger/ONE 128) BigInteger/ONE))))