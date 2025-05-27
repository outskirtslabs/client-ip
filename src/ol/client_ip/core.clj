(ns ol.client-ip.core
  "Core implementation of the client-ip library for extracting client IPs from forwarding headers.

  The client-ip library is designed to accurately determine the original client IP address
  from HTTP forwarding headers in Ring applications. It uses a strategy-based approach
  where different strategies handle different network configurations.

  ## Main Features

  * Strategy-based IP detection for different network setups
  * Processes IPs according to the chosen strategy to prevent spoofing
  * Supports all common headers: X-Forwarded-For, X-Real-IP, Forwarded (RFC 7239), etc.

  ## Usage

  The main entry point is the `wrap-client-ip` middleware function that requires
  a strategy and adds the `:ol/client-ip` key to the Ring request map:

  ```clojure
  (require '[ol.client-ip.core :refer [wrap-client-ip]]
           '[ol.client-ip.strategy :as strategy])

  (def app
    (-> handler
        (wrap-client-ip {:strategy (strategy/rightmost-non-private-strategy \"x-forwarded-for\")})
        ;; other middleware
        ))
  ```

  You can also use `from-request` to extract client IPs directly from requests:

  ```clojure
  (from-request request (strategy/rightmost-trusted-count-strategy \"x-forwarded-for\" 2))
  ;; => \"203.0.113.195\"
  ```

  See the strategy documentation for more details on choosing the right strategy."
  (:require [ol.client-ip.protocols :refer [client-ip]])
  (:import [java.net InetAddress]))

(defn from-request
  "Extract the client IP from a Ring request using the specified strategy.

  This is the core function for determining client IPs. It takes a Ring request
  and a strategy instance, then uses the strategy to determine the client IP
  from the request headers and remote address.

  Refer to ns docs and the [[wrap-client-ip]] docstring for more usage information.

  Returns the client InetAddress , or nil if no client IP can be determined."
  ^InetAddress [request strategy]
  (try
    (client-ip strategy (:headers request) (:remote-addr request))
    (catch Exception e
      (println "Error extracting client IP:" (.getMessage e))
      nil)))

(defn wrap-client-ip
  "Ring middleware that adds the client IP to the request map using strategies.

  This middleware extracts the original client IP address using the specified
  strategy and adds it to the request map as `:ol/client-ip`. The strategy determines
  how headers are processed and which IP is considered the client IP.

  ## Options

  The options map must contain:

  * `:strategy` - A strategy instance (required)

  ## Strategy Selection

  Choose the strategy that matches your network configuration:

  * `RemoteAddrStrategy` - Direct connections (no reverse proxy)
  * `SingleIPHeaderStrategy` - Single trusted reverse proxy with single IP headers
  * `RightmostNonPrivateStrategy` - Multiple proxies, all with private IPs
  * `RightmostTrustedCountStrategy` - Fixed number of trusted proxies
  * `RightmostTrustedRangeStrategy` - Known trusted proxy IP ranges
  * `ChainStrategy` - Try multiple strategies with fallback

  ## Examples

  ```clojure
  ;; Single reverse proxy with X-Real-IP
  (def app
    (-> handler
        (wrap-client-ip {:strategy (strategy/single-ip-header-strategy \"x-real-ip\")})
        ;; other middleware
        ))

  ;; Multiple proxies with private IPs
  (def app
    (-> handler
        (wrap-client-ip {:strategy (strategy/rightmost-non-private-strategy \"x-forwarded-for\")})
        ;; other middleware
        ))

  ;; Chain strategy with fallback
  (def app
    (-> handler
        (wrap-client-ip {:strategy
                          (strategy/chain-strategy 
                            [(strategy/single-ip-header-strategy \"x-real-ip\")
                             (strategy/remote-addr-strategy)])})
        ;; other middleware
        ))
  ```

  The middleware adds the `:ol/client-ip` key to the request map, containing the determined
  client InetAddress or nil."
  [handler options]
  (when-not (:strategy options)
    (throw (ex-info "Strategy is required in options map" {:options options})))
  (fn [request]
    (let [client-ip (from-request request (:strategy options))]
      (-> request
          (assoc :ol/client-ip client-ip)
          handler))))
