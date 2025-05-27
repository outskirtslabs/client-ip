(ns ol.client-ip.integration-test
  "Integration tests based on the Go realclientip library test suite.
   
   These tests verify compatibility with the Go implementation's behavior
   across all strategy types and edge cases."
  (:require [clojure.test :refer [deftest is testing]]
            [ol.client-ip.strategy :as strategy]
            [ol.client-ip.parse-ip :as parse-ip]
            [ol.client-ip.protocols :refer [client-ip]]))

;; Test Helper Functions

(defn ip
  "Parse IP string to InetAddress for testing."
  [ip-str]
  (parse-ip/from-string ip-str))

(defn- headers
  "Create Ring-style headers map from key-value pairs.
   Ring headers are lowercase strings."
  [& kvs]
  (into {} (map (fn [[k v]] [(name k) v]) (partition 2 kvs))))

(defn- test-cases
  "Run a series of test cases for a strategy constructor function.
   Each test case is a map with :name, :headers, :remote-addr, :expected, and optional :error.
   Strategy constructor args come from the test case map."
  [strategy-constructor-fn cases]
  (doseq [{:keys [name headers remote-addr expected error]
           :or   {headers {} remote-addr ""}
           :as   test-case} cases]
    (testing name
      (if error
        ;; Test should throw an exception
        (is (thrown? clojure.lang.ExceptionInfo
                     (apply strategy-constructor-fn (error test-case))))
        ;; Test should return expected result
        (let [strategy-args (remove #{:name :headers :remote-addr :expected :error}
                                    (keys test-case))
              strategy      (apply strategy-constructor-fn
                                   (map test-case strategy-args))]
          (is (= (when expected (ip expected)) (client-ip strategy headers remote-addr)) name))))))

;; Strategy Tests

(deftest remote-addr-strategy-test
  (test-cases strategy/remote-addr-strategy
              [{:name "IPv4 with port"
                :remote-addr "2.2.2.2:1234"
                :expected "2.2.2.2"}

               {:name "IPv4 with no port"
                :remote-addr "2.2.2.2"
                :expected "2.2.2.2"}

               {:name "IPv6 with port"
                :remote-addr "[2607:f8b0:4004:83f::18]:3838"
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with no port"
                :remote-addr "2607:f8b0:4004:83f::18"
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with zone and no port"
                :remote-addr "fe80::1111%eth0"
                :expected "fe80::1111%eth0"}

               {:name "IPv6 with zone and port"
                :remote-addr "[fe80::2222%eth0]:4848"
                :expected "fe80::2222%eth0"}

               {:name "IPv4-mapped IPv6"
                :remote-addr "[::ffff:172.21.0.6]:4747"
                :expected "172.21.0.6"}

               {:name "IPv4 loopback"
                :remote-addr "127.0.0.1"
                :expected "127.0.0.1"}

               {:name "IPv6 loopback"
                :remote-addr "::1"
                :expected "::1"}

               {:name "Garbage header (unused)"
                :headers (headers "x-forwarded-for" "!!!")
                :remote-addr "2.2.2.2:1234"
                :expected "2.2.2.2"}

               {:name "Fail: empty RemoteAddr"
                :remote-addr ""
                :expected nil}

               {:name "Fail: garbage RemoteAddr"
                :remote-addr "ohno"
                :expected nil}

               {:name "Fail: zero RemoteAddr IP"
                :remote-addr "0.0.0.0"
                :expected nil}

               {:name "Fail: unspecified RemoteAddr IP"
                :remote-addr "::"
                :expected nil}

               {:name "Fail: Unix domain socket"
                :remote-addr "@"
                :expected nil}]))

(deftest single-ip-header-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/single-ip-header-strategy ""))))

  (test-cases (fn [header-name] (strategy/single-ip-header-strategy header-name))
              [{:name "IPv4 with port"
                :header-name "true-client-ip"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "true-client-ip" "2.2.2.2:49489"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "2.2.2.2"}

               {:name "IPv4 with no port"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "true-client-ip" "2.2.2.2:49489"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "1.1.1.1"}

               {:name "IPv6 with port"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "[2607:f8b0:4004:83f::18]:3838"
                                  "true-client-ip" "2.2.2.2:49489"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with no port"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "2607:f8b0:4004:83f::19"
                                  "true-client-ip" "2.2.2.2:49489"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "2607:f8b0:4004:83f::19"}

               {:name "IPv6 with zone and no port"
                :header-name "a-b-c-d"
                :headers (headers "x-real-ip" "2607:f8b0:4004:83f::19"
                                  "a-b-c-d" "fe80::1111%zone"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "fe80::1111%zone"}

               {:name "IPv6 with zone and port"
                :header-name "a-b-c-d"
                :headers (headers "x-real-ip" "2607:f8b0:4004:83f::19"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "fe80::1111%zone"}

               {:name "IPv6 with brackets but no port"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "2607:f8b0:4004:83f::19"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "2607:f8b0:4004:83f::19"}

               {:name "IPv4-mapped IPv6"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "::ffff:172.21.0.6"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "172.21.0.6"}

               {:name "IPv4-mapped IPv6 in IPv6 form"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "[64:ff9b::188.0.2.128]:4747"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "64:ff9b::bc00:280"}

               {:name "6to4 IPv4-mapped IPv6"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "2002:c000:204::"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "2002:c000:204::"}

               {:name "IPv4 loopback"
                :header-name "x-real-ip"
                :headers (headers "x-real-ip" "127.0.0.1"
                                  "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected "127.0.0.1"}

               {:name "Fail: missing header"
                :header-name "x-real-ip"
                :headers (headers "a-b-c-d" "[fe80::1111%zone]:4848"
                                  "x-forwarded-for" "3.3.3.3")
                :expected nil}

               {:name "Fail: garbage IP"
                :header-name "true-client-ip"
                :headers (headers "x-real-ip" "::1"
                                  "true-client-ip" "nope"
                                  "x-forwarded-for" "3.3.3.3")
                :expected nil}

               {:name "Fail: zero IP"
                :header-name "true-client-ip"
                :headers (headers "x-real-ip" "::1"
                                  "true-client-ip" "0.0.0.0"
                                  "x-forwarded-for" "3.3.3.3")
                :expected nil}]))

(deftest rightmost-non-private-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-non-private-strategy ""))))

  (test-cases (fn [header-name] (strategy/rightmost-non-private-strategy header-name))
              [{:name "IPv4 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4:39333")
                :expected "4.4.4.4"}

               {:name "IPv4 with no port"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=5.5.5.5, For=6.6.6.6")
                :expected "6.6.6.6"}

               {:name "IPv6 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "[2607:f8b0:4004:83f::18]:3838")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with no port"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "host=what;for=6.6.6.6;proto=https, Host=blah;For=\"2607:f8b0:4004:83f::18\";Proto=https")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with port and zone"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "host=what;for=6.6.6.6;proto=https, For=\"[2607:f8b0:4004:83f::18%eth0]:3393\";Proto=https, Host=blah;For=\"[fe80::1111%zone]:9943\";Proto=https")
                :expected "2607:f8b0:4004:83f::18%eth0"}

               {:name "IPv6 with port and zone, no quotes"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "host=what;for=6.6.6.6;proto=https, For=\"[2607:f8b0:4004:83f::18%eth0]:3393\";Proto=https, Host=blah;For=[fe80::1111%zone]:9943;Proto=https")
                :expected "2607:f8b0:4004:83f::18%eth0"}

               {:name "IPv4-mapped IPv6"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "3.3.3.3, 4.4.4.4, ::ffff:188.0.2.128"
                                  "forwarded" "Host=blah;For=\"7.7.7.7\";Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "188.0.2.128"}

               {:name "IPv4-mapped IPv6 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "3.3.3.3, 4.4.4.4,[::ffff:188.0.2.128]:48483"
                                  "forwarded" "Host=blah;For=\"7.7.7.7\";Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "188.0.2.128"}

               {:name "IPv4-mapped IPv6 in IPv6 (hex) form"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "[::ffff:188.0.2.128]:48483, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "host=what;for=6.6.6.6;proto=https, For=\"::ffff:bc15:0006\"")
                :expected "188.21.0.6"}

               {:name "NAT64 IPv4-mapped IPv6"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "3.3.3.3, 4.4.4.4, 64:ff9b::188.0.2.128"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "64:ff9b::bc00:280"}

               {:name "XFF: rightmost not desirable"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, nope"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "5.5.5.5"}

               {:name "Forwarded: rightmost not desirable"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 4.4.4.4, 5.5.5.5"
                                  "forwarded" "host=what;for=:48485;proto=https,For=2.2.2.2, For=\"\", For=\"::ffff:192.168.1.1\"")
                :expected "2.2.2.2"}

               {:name "Private IPs filtered out"
                :header-name "x-forwarded-for"
                :headers (headers "x-forwarded-for" "2.2.2.2, 192.168.1.1, 10.0.0.1, 3.3.3.3")
                :expected "3.3.3.3"}

               {:name "Fail: XFF: none acceptable"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 192.168.1.1, !?!, ::, 0.0.0.0"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"fe80::abcd%zone\"")
                :expected nil}

               {:name "Fail: Forwarded: none acceptable"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 192.168.1.1, 2.2.2.2"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"::ffff:ac15:0006%zone\", For=\"::\", For=0.0.0.0")
                :expected nil}

               {:name "Fail: XFF: no header"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"::ffff:ac15:0006%zone\"")
                :remote-addr "9.9.9.9"
                :expected nil}

               {:name "Fail: Forwarded: no header"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "64:ff9b::188.0.2.128, 3.3.3.3, 4.4.4.4")
                :expected nil}

               {:name "Fail: all private IPs"
                :header-name "x-forwarded-for"
                :headers (headers "x-forwarded-for" "192.168.1.1, 10.0.0.1, 172.16.1.1")
                :expected nil}

               {:name "Fail: empty header"
                :header-name "x-forwarded-for"
                :headers (headers "x-forwarded-for" "")
                :expected nil}

               {:name "Fail: missing header"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1")
                :expected nil}]))

(deftest leftmost-non-private-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/leftmost-non-private-strategy ""))))

  (test-cases (fn [header-name] (strategy/leftmost-non-private-strategy header-name))
              [{:name "IPv4 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :expected "2.2.2.2"}

               {:name "IPv4 with no port"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=5.5.5.5, For=6.6.6.6")
                :expected "5.5.5.5"}

               {:name "IPv6 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "[2607:f8b0:4004:83f::18]:3838, 3.3.3.3, 4.4.4.4")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with no port"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "Host=blah;For=\"2607:f8b0:4004:83f::18\";Proto=https")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "IPv6 with port and zone"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=[fe80::1111%zone], Host=blah;For=\"[2607:f8b0:4004:83f::18%zone]:9943\";Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "2607:f8b0:4004:83f::18%zone"}

               {:name "IPv6 with port and zone, no quotes"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=[fe80::1111%zone], Host=blah;For=[2607:f8b0:4004:83f::18%zone]:9943;Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "2607:f8b0:4004:83f::18%zone"}

               {:name "IPv4-mapped IPv6"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::ffff:188.0.2.128, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "Host=blah;For=\"7.7.7.7\";Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "188.0.2.128"}

               {:name "IPv4-mapped IPv6 with port"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "[::ffff:188.0.2.128]:48483, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "Host=blah;For=\"7.7.7.7\";Proto=https, host=what;for=6.6.6.6;proto=https")
                :expected "188.0.2.128"}

               {:name "IPv4-mapped IPv6 in IPv6 (hex) form"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "[::ffff:188.0.2.128]:48483, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "188.21.0.6"}

               {:name "NAT64 IPv4-mapped IPv6"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "64:ff9b::188.0.2.128, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "64:ff9b::bc00:280"}

               {:name "XFF: leftmost not desirable"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 4.4.4.4, 5.5.5.5"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "4.4.4.4"}

               {:name "Forwarded: leftmost not desirable"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 4.4.4.4, 5.5.5.5"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"2607:f8b0:4004:83f::18\"")
                :expected "2607:f8b0:4004:83f::18"}

               {:name "Skip private IPs to find first non-private"
                :header-name "x-forwarded-for"
                :headers (headers "x-forwarded-for" "192.168.1.1, 10.0.0.1, 2.2.2.2, 3.3.3.3")
                :expected "2.2.2.2"}

               {:name "Fail: XFF: none acceptable"
                :header-name "x-forwarded-for"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, ::, 0.0.0.0, 192.168.1.1, !?!"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"fe80::abcd%zone\"")
                :expected nil}

               {:name "Fail: Forwarded: none acceptable"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::1, nope, 192.168.1.1, 2.2.2.2"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"::ffff:ac15:0006%zone\",For=\"::\",For=0.0.0.0")
                :expected nil}

               {:name "Fail: XFF: no header"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "forwarded" "For=\"\", For=\"::ffff:192.168.1.1\", host=what;for=:48485;proto=https,For=\"::ffff:ac15:0006%zone\"")
                :expected nil}

               {:name "Fail: Forwarded: no header"
                :header-name "forwarded"
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "64:ff9b::188.0.2.128, 3.3.3.3, 4.4.4.4")
                :expected nil}

               {:name "Fail: all private IPs"
                :header-name "x-forwarded-for"
                :headers (headers "x-forwarded-for" "192.168.1.1, 10.0.0.1, 172.16.1.1")
                :expected nil}]))

(deftest rightmost-trusted-count-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "x-forwarded-for" 0)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "x-forwarded-for" -1)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "" 1))))

  (test-cases (fn [header-name trusted-count]
                (strategy/rightmost-trusted-count-strategy header-name trusted-count))
              [{:name "Count one"
                :header-name "forwarded"
                :trusted-count 1
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "188.21.0.6"}

               {:name "Count five"
                :header-name "x-forwarded-for"
                :trusted-count 5
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28, 7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10, 11.11.11.11, 12.12.12.12"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected "fe80::382b:141b:fa4a:2a16%28"}

               {:name "Fail: header too short/count too large"
                :header-name "x-forwarded-for"
                :trusted-count 50
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28, 7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12"
                                  "forwarded" "For=\"::ffff:bc15:0006\", host=what;for=6.6.6.6;proto=https")
                :expected nil}

               {:name "Fail: bad value at count index"
                :header-name "forwarded"
                :trusted-count 2
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28, 7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12"
                                  "forwarded" "For=\"::ffff:bc15:0006\", For=nope, host=what;for=6.6.6.6;proto=https")
                :expected nil}

               {:name "Fail: zero value at count index"
                :header-name "forwarded"
                :trusted-count 2
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28, 7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12"
                                  "forwarded" "For=\"::ffff:bc15:0006\", For=0.0.0.0, host=what;for=6.6.6.6;proto=https")
                :expected nil}

               {:name "Fail: header missing"
                :header-name "forwarded"
                :trusted-count 1
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "4.4.4.4, 5.5.5.5, ::1, fe80::382b:141b:fa4a:2a16%28, 7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12")
                :expected nil}]))

(deftest rightmost-trusted-range-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "" [])))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "not-xff-or-forwarded" []))))

  (test-cases (fn [header-name trusted-ranges]
                (strategy/rightmost-trusted-range-strategy header-name trusted-ranges))
              [{:name "One range"
                :header-name "x-forwarded-for"
                :trusted-ranges ["4.4.4.0/24"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :expected "3.3.3.3"}

               {:name "One IP"
                :header-name "x-forwarded-for"
                :trusted-ranges ["4.4.4.4/32"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :expected "3.3.3.3"}

               {:name "Many kinds of ranges"
                :header-name "forwarded"
                :trusted-ranges ["2.2.2.2/32" "2607:f8b0:4004:83f::200e/128"
                                 "3.3.0.0/16" "2001:db7::/64"
                                 "::ffff:4.4.4.4/124" "64:ff9b::188.0.2.128/112"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4"
                                  "forwarded" "For=99.99.99.99, For=4.4.4.8, For=\"[2607:f8b0:4004:83f::200e]:4747\", For=2.2.2.2:8883, For=64:ff9b::188.0.2.200, For=3.3.5.5, For=2001:db7::abcd")
                :expected "4.4.4.8"}

               {:name "Fail: no non-trusted IP"
                :header-name "x-forwarded-for"
                :trusted-ranges ["2.2.2.0/24"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "2.2.2.2:3384, 2.2.2.3, 2.2.2.4")
                :expected nil}

               {:name "Fail: rightmost non-trusted IP invalid"
                :header-name "x-forwarded-for"
                :trusted-ranges ["2.2.2.0/24"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "nope, 2.2.2.2:3384, 2.2.2.3, 2.2.2.4")
                :expected nil}

               {:name "Fail: rightmost non-trusted IP unspecified"
                :header-name "x-forwarded-for"
                :trusted-ranges ["2.2.2.0/24"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "::, 2.2.2.2:3384, 2.2.2.3, 2.2.2.4")
                :expected nil}

               {:name "Fail: no values in header"
                :header-name "x-forwarded-for"
                :trusted-ranges ["2.2.2.0/24"]
                :headers (headers "x-real-ip" "1.1.1.1"
                                  "x-forwarded-for" "")
                :expected nil}]))

(deftest chain-strategy-test
  (testing "Constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/chain-strategy [])))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/chain-strategy ["not-a-strategy"]))))

  (test-cases (fn [strategies] (strategy/chain-strategy strategies))
              [{:name        "Single strategy"
                :strategies  [(strategy/remote-addr-strategy)]
                :headers     (headers "x-real-ip" "1.1.1.1"
                                      "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :remote-addr "5.5.5.5"
                :expected    "5.5.5.5"}

               {:name        "Multiple strategies"
                :strategies  [(strategy/rightmost-non-private-strategy "forwarded")
                              (strategy/single-ip-header-strategy "true-client-ip")
                              (strategy/single-ip-header-strategy "x-real-ip")
                              (strategy/remote-addr-strategy)]
                :headers     (headers "x-real-ip" "1.1.1.1"
                                      "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :remote-addr "5.5.5.5"
                :expected    "1.1.1.1"}

               {:name        "First strategy succeeds"
                :strategies  [(strategy/single-ip-header-strategy "x-real-ip")
                              (strategy/remote-addr-strategy)]
                :headers     (headers "x-real-ip" "1.1.1.1"
                                      "x-forwarded-for" "2.2.2.2")
                :remote-addr "5.5.5.5"
                :expected    "1.1.1.1"}

               {:name        "Fallback to second strategy"
                :strategies  [(strategy/single-ip-header-strategy "missing-header")
                              (strategy/rightmost-non-private-strategy "x-forwarded-for")]
                :headers     (headers "x-real-ip" "1.1.1.1"
                                      "x-forwarded-for" "192.168.1.1, 2.2.2.2")
                :remote-addr "5.5.5.5"
                :expected    "2.2.2.2"}

               {:name        "Fail: Multiple strategies, all fail"
                :strategies  [(strategy/rightmost-non-private-strategy "forwarded")
                              (strategy/single-ip-header-strategy "true-client-ip")
                              (strategy/single-ip-header-strategy "x-real-ip")
                              (strategy/remote-addr-strategy)]
                :headers     (headers "x-forwarded-for" "2.2.2.2:3384, 3.3.3.3, 4.4.4.4")
                :remote-addr ""
                :expected    nil}]))

(deftest forwarded-header-rfc7239-test
  (testing "Rightmost non-private with Forwarded header"
    (let [strategy (strategy/rightmost-non-private-strategy "forwarded")]
      (is (= (ip "5.5.5.5")
             (client-ip strategy
                        (headers "forwarded" "For=1.1.1.1;Proto=https, For=192.168.1.1;Proto=https, For=5.5.5.5;Proto=https")
                        "")))

      (is (= (ip "2607:f8b0:4004:83f::18")
             (client-ip strategy
                        (headers "forwarded" "Host=blah;For=\"2607:f8b0:4004:83f::18\";Proto=https")
                        "")))

      ;; Test with link-local IPv6 which is correctly filtered as private
      (is (= nil
             (client-ip strategy
                        (headers "forwarded" "Host=blah;For=\"[fe80::2222%eth0]:4848\";Proto=https")
                        ""))))

    (testing "Chain strategy with Forwarded fallback"
      (let [strategy (strategy/chain-strategy
                      [(strategy/single-ip-header-strategy "x-real-ip")
                       (strategy/rightmost-non-private-strategy "forwarded")])]
        (is (= (ip "1.1.1.1")
               (client-ip strategy
                          (headers "x-real-ip" "1.1.1.1"
                                   "forwarded" "For=2.2.2.2")
                          "")))

        (is (= (ip "2.2.2.2")
               (client-ip strategy
                          (headers "forwarded" "For=192.168.1.1, For=2.2.2.2")
                          "")))))))
