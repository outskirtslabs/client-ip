;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.strategy-test
  (:require [clojure.test :refer [deftest is testing are]]
            [ol.client-ip.strategy :as strategy]
            [ol.client-ip.parse-ip :as parse-ip]
            [ol.client-ip.protocols :refer [client-ip]]))

(defn ip [ip-str]
  (parse-ip/from-string ip-str))

(deftest test-split-host-zone
  (are [expected input] (= expected (strategy/split-host-zone input))
    ["192.168.1.1" nil] "192.168.1.1"
    ["fe80::1" "1"]     "fe80::1%1"
    ["fe80::1" "eth0"]  "fe80::1%eth0"
    ["2001:db8::1" nil] "2001:db8::1"
    [nil nil]           nil))

(deftest test-remote-addr-strategy
  (let [strategy (strategy/remote-addr-strategy)]
    (are [expected input] (= (when expected (ip expected)) (client-ip strategy {} input))
      "192.168.1.1" "192.168.1.1:8080"
      "192.168.1.1" "192.168.1.1"
      "2001:db8::1" "[2001:db8::1]:8080"
      "2001:db8::1" "2001:db8::1"
      nil           "0.0.0.0:8080"
      nil           "[::]:8080"
      nil           nil
      nil           ""
      nil           "not-an-ip:8080")))

(deftest test-single-ip-header-strategy
  (testing "constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/single-ip-header-strategy ""))))

  (let [strategy (strategy/single-ip-header-strategy "x-real-ip")]
    (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-real-ip" input} ""))
      "192.168.1.1" "192.168.1.1"
      "192.168.1.1" "192.168.1.1:8080"
      "2001:db8::1" "[2001:db8::1]"
      nil           "0.0.0.0"
      nil           "::"
      nil           "")

    (testing "header not present"
      (is (= nil (client-ip strategy {} ""))))

    (testing "header name exactly as Ring provides (lowercase)"
      (is (= (ip "192.168.1.1")
             (client-ip strategy {"x-real-ip" "192.168.1.1"} ""))))))

(deftest test-rightmost-non-private-strategy
  (testing "constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-non-private-strategy ""))))

  (let [strategy (strategy/rightmost-non-private-strategy "x-forwarded-for")]
    (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-forwarded-for" input} ""))
      "8.8.8.8" "1.1.1.1, 192.168.1.1, 10.0.0.1, 8.8.8.8"
      nil       "192.168.1.1, 10.0.0.1, 172.16.0.1"
      "8.8.8.8" "8.8.8.8"
      nil       ""
      "8.8.8.8" "invalid-ip, 192.168.1.1, 8.8.8.8")

    (testing "header not present"
      (is (= nil (client-ip strategy {} ""))))

    (testing "RFC 7239 Forwarded header parsing"
      (let [forwarded-strategy (strategy/rightmost-non-private-strategy "forwarded")]
        (is (= (ip "8.8.8.8")
               (client-ip forwarded-strategy {"forwarded" "for=1.1.1.1;proto=https, for=192.168.1.1;proto=https, for=8.8.8.8;proto=https"} "")))))

    (testing "Forwarded header with ports"
      (let [forwarded-strategy (strategy/rightmost-non-private-strategy "forwarded")]
        (is (= (ip "8.8.8.8")
               (client-ip forwarded-strategy {"forwarded" "for=\"[2001:db8::1]:8080\";proto=https, for=\"192.168.1.1:8080\";proto=https, for=\"8.8.8.8:8080\";proto=https"} "")))))))

(deftest test-leftmost-non-private-strategy
  (let [strategy (strategy/leftmost-non-private-strategy "x-forwarded-for")]
    (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-forwarded-for" input} ""))
      "1.1.1.1" "1.1.1.1, 192.168.1.1, 10.0.0.1, 8.8.8.8"
      "8.8.8.8" "192.168.1.1, 10.0.0.1, 8.8.8.8, 1.1.1.1"
      nil       "192.168.1.1, 10.0.0.1, 172.16.0.1"
      "8.8.8.8" "8.8.8.8")))

(deftest test-rightmost-trusted-count-strategy
  (testing "constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "" 1)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "x-forwarded-for" 0)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-count-strategy "x-forwarded-for" -1))))

  (testing "single trusted proxy"
    (let [strategy (strategy/rightmost-trusted-count-strategy "x-forwarded-for" 1)]
      (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-forwarded-for" input} ""))
        "1.1.1.1" "1.1.1.1, 192.168.1.1"
        "192.168.1.1" "1.1.1.1, 192.168.1.1, 10.0.0.1"
        nil "192.168.1.1")

      (testing "header not present"
        (is (= nil (client-ip strategy {} ""))))))

  (testing "two trusted proxies"
    (let [strategy (strategy/rightmost-trusted-count-strategy "x-forwarded-for" 2)]
      (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-forwarded-for" input} ""))
        "1.1.1.1" "1.1.1.1, 192.168.1.1, 10.0.0.1"
        "8.8.8.8" "1.1.1.1, 8.8.8.8, 192.168.1.1, 10.0.0.1"
        nil "1.1.1.1, 192.168.1.1"))))

(deftest test-rightmost-trusted-range-strategy
  (testing "constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "" ["10.0.0.0/8"])))

    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "x-forwarded-for" [])))

    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "x-forwarded-for" nil)))

    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/rightmost-trusted-range-strategy "x-forwarded-for" ["invalid-cidr"]))))

  (let [strategy (strategy/rightmost-trusted-range-strategy "x-forwarded-for" ["10.0.0.0/8" "192.168.0.0/16"])]
    (are [expected input] (= (when expected (ip expected)) (client-ip strategy {"x-forwarded-for" input} ""))
      "8.8.8.8" "1.1.1.1, 192.168.1.1, 10.0.0.1, 8.8.8.8"
      "8.8.8.8" "1.1.1.1, 8.8.8.8, 192.168.1.1, 10.0.0.1"
      nil       "192.168.1.1, 10.0.0.1, 192.168.2.1"
      "8.8.8.8" "8.8.8.8"
      nil       "")

    (testing "header not present"
      (is (= nil (client-ip strategy {} ""))))))

(deftest test-chain-strategy
  (testing "constructor validation"
    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/chain-strategy [])))

    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/chain-strategy nil)))

    (is (thrown? clojure.lang.ExceptionInfo
                 (strategy/chain-strategy ["not-a-strategy"]))))

  (testing "single strategy in chain"
    (let [strategy (strategy/chain-strategy [(strategy/remote-addr-strategy)])]
      (is (= (ip "192.168.1.1") (client-ip strategy {} "192.168.1.1:8080")))))

  (testing "multiple strategies - first succeeds"
    (let [strategy (strategy/chain-strategy [(strategy/single-ip-header-strategy "x-real-ip")
                                             (strategy/remote-addr-strategy)])]
      (is (= (ip "1.1.1.1") (client-ip strategy {"x-real-ip" "1.1.1.1"} "192.168.1.1:8080")))))

  (testing "multiple strategies - fallback to second"
    (let [strategy (strategy/chain-strategy [(strategy/single-ip-header-strategy "x-real-ip")
                                             (strategy/remote-addr-strategy)])]
      (is (= (ip "192.168.1.1") (client-ip strategy {} "192.168.1.1:8080")))
      (is (= (ip "192.168.1.1") (client-ip strategy {"x-real-ip" "0.0.0.0"} "192.168.1.1:8080")))))

  (testing "all strategies fail"
    (let [strategy (strategy/chain-strategy [(strategy/single-ip-header-strategy "x-real-ip")
                                             (strategy/single-ip-header-strategy "cf-connecting-ip")])]
      (is (= nil (client-ip strategy {} ""))))))