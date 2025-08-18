;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.cidr-test
  (:require [ol.client-ip.cidr :as sut]
            [clojure.test :refer [deftest testing are]]))

(deftest test-cidr-contains-ipv4
  (testing "IPv4 CIDR ranges"
    (are [cidr ip expected] (= expected (sut/contains? cidr ip))
      "192.168.1.0/24" "192.168.1.0"     true
      "192.168.1.0/24" "192.168.1.1"     true
      "192.168.1.0/24" "192.168.1.127"   true
      "192.168.1.0/24" "192.168.1.255"   true
      "192.168.1.0/24" "192.168.0.255"   false
      "192.168.1.0/24" "192.168.2.0"     false
      "172.16.0.0/16"  "172.16.0.0"      true
      "172.16.0.0/16"  "172.16.0.1"      true
      "172.16.0.0/16"  "172.16.255.0"    true
      "172.16.0.0/16"  "172.16.255.255"  true
      "172.16.0.0/16"  "172.15.255.255"  false
      "172.16.0.0/16"  "172.17.0.0"      false
      "10.0.0.0/8"     "10.0.0.0"        true
      "10.0.0.0/8"     "10.0.0.1"        true
      "10.0.0.0/8"     "10.255.255.254"  true
      "10.0.0.0/8"     "10.255.255.255"  true
      "10.0.0.0/8"     "9.255.255.255"   false
      "10.0.0.0/8"     "11.0.0.0"        false
      "192.168.1.0/28" "192.168.1.0"     true
      "192.168.1.0/28" "192.168.1.15"    true
      "192.168.1.0/28" "192.168.1.16"    false
      "192.168.1.1/32" "192.168.1.1"     true
      "192.168.1.1/32" "192.168.1.0"     false
      "192.168.1.1/32" "192.168.1.2"     false
      "0.0.0.0/0"      "0.0.0.0"         true
      "0.0.0.0/0"      "255.255.255.255" true
      "0.0.0.0/0"      "192.168.1.1"     true)))

(deftest test-cidr-contains-ipv6
  (testing "IPv6 CIDR ranges"
    (are [cidr ip expected] (= expected (sut/contains? cidr ip))
      "2001:db8::/32"   "2001:db8::1"                             true
      "2001:db8::/32"   "2001:db8:ffff::1"                        true
      "2001:db8::/32"   "2001:db7:ffff::1"                        false
      "2001:db8::/32"   "2001:db9::1"                             false
      "2001:db8::/64"   "2001:db8::1"                             true
      "2001:db8::/64"   "2001:db8::ffff:ffff:ffff:ffff"           true
      "2001:db8::/64"   "2001:db8:0:1::1"                         false
      "2001:db8::1/128" "2001:db8::1"                             true
      "2001:db8::1/128" "2001:db8::2"                             false
      "::/0"            "::"                                      true
      "::/0"            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" true
      "::/0"            "2001:db8::1"                             true)))

(deftest test-cidr-contains-invalid-inputs
  (testing "Invalid inputs"
    (are [cidr ip] (false? (sut/contains? cidr ip))
      ;; mixed types
      "192.168.1.0/24"      "2001:db8::1"
      "2001:db8::/32"       "192.168.1.1"
      ;; invalid CIDR notation
      "not-a-cidr"          "192.168.1.1"
      "192.168.1.0/invalid" "192.168.1.1"
      "192.168.1.0/33"      "192.168.1.1"
      "2001:db8::/129"      "2001:db8::1"
      ;; invalid IP
      "192.168.1.0/24"      "not-an-ip"
      "192.168.1.0/24"      "999.999.999.999"
      "2001:db8::/32"       "not-an-ip"
      ;; nil input
      nil                   "192.168.1.1"
      "192.168.1.0/24"      nil
      nil                   nil)))