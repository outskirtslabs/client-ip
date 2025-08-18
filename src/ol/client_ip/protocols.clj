;; Copyright © 2025 Casey Link <casey@outskirtslabs.com>
;; SPDX-License-Identifier: MIT
(ns ol.client-ip.protocols)

(defprotocol ClientIPStrategy
  "Protocol for determining client IP from headers and remote address.

  Returns InetAddress or nil if no valid client ip is found.

  Implementations should:
  * Be thread-safe and reusable across requests
  * Validate configuration at creation time (throw on invalid config) "
  (client-ip [this headers remote-addr]
    "Extract the client IP from request headers and remote address.
    
    Args:
      headers: Ring-style headers map (lowercase keys)
      remote-addr: String from Ring request :remote-addr
    
    Returns:
      InetAddress or nil if no valid client IP found."))