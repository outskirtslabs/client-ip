;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [ol.client-ip.core :as core]
            [ol.client-ip.parse-ip :as parse-ip]
            [ol.client-ip.strategy :as strategy]))

(defn ip [ip-str]
  (parse-ip/from-string ip-str))

(deftest wrap-client-ip-test
  (testing "Middleware requires strategy"
    (is (thrown? clojure.lang.ExceptionInfo
                 (core/wrap-client-ip identity {}))))

  (testing "Middleware with strategy"
    (let [handler    (fn [request] {:status 200 :body (:ol/client-ip request)})
          middleware (core/wrap-client-ip handler {:strategy (strategy/single-ip-header-strategy "x-real-ip")})
          request    {:headers {"x-real-ip" "203.0.113.195"} :remote-addr "10.0.0.1:8080"}
          response   (middleware request)]
      (is (= (ip "203.0.113.195") (:body response)))))

  (testing "Middleware with chain strategy"
    (let [handler    (fn [request] {:status 200 :body (:ol/client-ip request)})
          middleware (core/wrap-client-ip handler
                                          {:strategy (strategy/chain-strategy
                                                      [(strategy/single-ip-header-strategy "x-real-ip")
                                                       (strategy/remote-addr-strategy)])})
          request    {:headers {} :remote-addr "203.0.113.195:8080"}
          response   (middleware request)]
      (is (= (ip "203.0.113.195") (:body response)))))

  (testing "Middleware when no IP found"
    (let [handler    (fn [request] {:status 200 :body (:ol/client-ip request)})
          middleware (core/wrap-client-ip handler {:strategy (strategy/rightmost-non-private-strategy "x-forwarded-for")})
          request    {:headers {"x-forwarded-for" "192.168.1.1, 10.0.0.1"} :remote-addr "172.16.0.1:8080"}
          response   (middleware request)]
      (is (nil? (:body response))))))