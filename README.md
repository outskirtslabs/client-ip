# client-ip

> A 0-dependency ring middleware for determining a request's real client IP address from HTTP headers

`X-Forwarded-For` and other client IP headers are [often used
incorrectly](https://adam-p.ca/blog/2022/03/x-forwarded-for/), resulting in bugs
and security vulnerabilities. This library provides strategies for extracting
the correct client IP based on your network configuration.

It is based on the golang reference implementation [realclientip/realclientip-go](https://github.com/realclientip/realclientip-go).

Quicky feature list:

* ring middleware determining the client's ip address
* 0 dependency IP address string parsing with guaranteed no trips to the hosts' DNS services, which can block and timeout (unlike Java's `InetAddress/getByName`)
* rightmost-ish strategies support the `X-Forwarded-For` and `Forwarded` (RFC 7239) headers.
* IPv6 zone identifiers support

Note that there is no dependency on ring, the public api could also be used for pedestal or sieppari-style interceptors.

## Installation

[![Clojars Project](https://img.shields.io/clojars/v/com.outskirtslabs/client-ip.svg)](https://clojars.org/com.outskirtslabs/client-ip)

```clojure
;; deps.edn
{:deps {com.outskirtslabs/client-ip {:mvn/version "0.1.0"}}}

;; Leiningen
[com.outskirtslabs/client-ip "0.1.0"]
```

## Quick Start

```clojure
(ns myapp.core
  (:require [ol.client-ip.core :as client-ip]
            [ol.client-ip.strategy :as strategy]))

;; Simple case: behind a trusted proxy that sets X-Real-IP
(def app
  (-> handler
      (client-ip/wrap-client-ip
        {:strategy (strategy/single-ip-header-strategy "x-real-ip")})))

;; The client IP is now available in the request
(defn handler [request]
  (let [client-ip (:ol/client-ip request)]
    {:status 200 
     :body (str "Your IP is: " client-ip)}))
```

👉 For detailed guidance on choosing strategies, see [doc/usage.md](doc/usage.md).

Choosing the wrong strategy can result in ip address spoofing security vulnerabilities.

## Recommended Reading

You think it is an easy question:

> I have an HTTP application, I just want to know the IP address of my client.

But who is the client?

> The computer on the other end of the network connection?

But which network connection? The one connected to your http application is probably a reverse proxy or load balancer

> Well I mean the "user's ip address"

It ain't so easy kid.

There are many good articles on the internet that discuss the perils and pitfalls of trying to answer this deceptively simple question. 

You *should* read one or two of them to get an idea of the complexity in this
space. Libraries, like this one, *cannot* hide the complexity from you, there is
no abstraction nor encapsulation nor "default best practice".

Below are some of those good articles:

* MDN: [X-Forwarded-For: Security and privacy concerns](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#security_and_privacy_concerns)
* [The perils of the “real” client IP](https://adam-p.ca/blog/2022/03/x-forwarded-for/) ([archive link](https://web.archive.org/web/20250416042714/https://adam-p.ca/blog/2022/03/x-forwarded-for/))
* [Rails IP Spoofing Vulnerabilities and Protection](https://www.gingerlime.com/2012/rails-ip-spoofing-vulnerabilities-and-protection/)  ([archive link](https://web.archive.org/web/20250421121810/https://www.gingerlime.com/2012/rails-ip-spoofing-vulnerabilities-and-protection/))

## Security

See [here][sec] for security advisories or to report a security vulnerability.

## License

Copyright © 2025 Casey Link <casey@outskirtslabs.com>

Distributed under the [MIT License](./LICENSE)

[sec]: https://github.com/outskirtslabs/client-ip/security/advisories
