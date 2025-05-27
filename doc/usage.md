# Usage Guide

This guide explains when and why to use each strategy. The choice of strategy is
critical - **using the wrong strategy can lead to ip spoofing vulnerabilities**.

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [Usage Guide](#usage-guide)
  - [Understanding Your Network Setup](#understanding-your-network-setup)
  - [Terminology](#terminology)
  - [Strategy Reference](#strategy-reference)
    - [Remote Address Strategy / No middleware at all!](#remote-address-strategy--no-middleware-at-all)
    - [Single IP Header Strategy](#single-ip-header-strategy)
    - [Rightmost Non-Private Strategy](#rightmost-non-private-strategy)
    - [Rightmost Trusted Count Strategy](#rightmost-trusted-count-strategy)
    - [Rightmost Trusted Range Strategy](#rightmost-trusted-range-strategy)
    - [Chain Strategy](#chain-strategy)
    - [Leftmost Non-Private Strategy](#leftmost-non-private-strategy)
  - [Testing Your Configuration](#testing-your-configuration)
  - [Common Pitfalls](#common-pitfalls)

<!-- markdown-toc end -->


## Understanding Your Network Setup

Before choosing a strategy, you need to understand your production environment's network topology:

1. **Are you behind reverse proxies?** (nginx, Apache, load balancers, CDNs)
2. **How many trusted proxies are there?**
3. **What headers do they set?**

The answers determine which strategy is appropriate and secure for your setup.


## Terminology

- **socket-level IP**: The IP address that a server or proxy observes at the TCP socket level from whatever is directly connecting to it. This is always trustworthy since it cannot be spoofed at the socket level, regardless of whether the connection is from an end user or another proxy in the chain.

- **private ip addresses**: IP addresses reserved for private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.) that are not routable on the public internet. These typically represent your internal infrastructure components.

- **reverse proxy / proxy / load balancer / CDN**: An intermediary server that sits between clients and your application server, forwarding client requests. Examples include: nginx, Apache, caddy, AWS ALB, Cloudflare, Cloudfront, Fastly, Akamai, Fly.io, Hetzner Load Balancer.

- **trusted proxy**: A reverse proxy under your control or operated by a service you trust, whose IP forwarding headers you can rely on. The key characteristic is that you know what headers it sets and clients cannot bypass it.

- **ip spoofing**: The practice of sending packets with a forged source IP address, or in the context of HTTP headers, setting fake client IP values in headers like `X-Forwarded-For` to deceive the application about the request's true origin.

- **trivially spoofable**: Headers or IP values that can be easily faked by any client without special network access. For example, any client can send `X-Forwarded-For: 1.2.3.4` in their request.

- **XFF**: Short for `X-Forwarded-For`, the most common HTTP header used by proxies to communicate the original client IP address through a chain of proxies. Each proxy typically appends the IP it received the request from.

- **rightmost-ish**: A parsing strategy that extracts IP addresses from the right side of forwarding headers like `X-Forwarded-For`, typically skipping a known number of trusted proxies to find the IP added by the first trusted proxy. This is the only trustworthy approach since you control what your trusted proxies add to the header chain ([see this article][adam-p]).

- **leftmost-ish**: A parsing strategy that takes the leftmost (first) IP address in forwarding headers, representing the alleged original client. This is highly untrustworthy and vulnerable to spoofing since any client can set arbitrary values at the beginning of these headers ([see this article][adam-p]).


[adam-p]: https://adam-p.ca/blog/2022/03/x-forwarded-for

## Strategy Reference

### Remote Address Strategy / No middleware at all!

**When to use:**

- Your server accepts direct connections from clients without any reverse proxies or load balancers


**Why:** The socket-level remote address is the actual client IP when there are no intermediaries.


Using this library you can use the remote-addr-strategy, which is provided to be comprehensive, however you can also just use the existing [`:remote-addr`](https://github.com/ring-clojure/ring/blob/master/SPEC.md#remote-addr) key in your ring request map.

```clojure
(strategy/remote-addr-strategy)

;; OR, just fetch the remote addr from the ring request map

(:remote-addr request)
```

**Example network:**
```
Client -> Your Server
```

**Security:** Safe - the remote address cannot be spoofed at the socket level.

---

### Single IP Header Strategy

**When to use:** You have a trusted reverse proxy that accepts connections directly from clients and sets a specific header with the client IP.

**Why:** Many Cloud Provider's CDNs and load balancers products provide a single authoritative header with the real client IP. This is the most secure approach when you have such a setup.

**Provider headers with trusted values:**

- Cloudflare (everyone): `cf-connecting-ip` - this is a socket-level IP value ([docs][ip-cf])
- Cloudflare (enterprise): `true-client-ip` - also a socket-level IP value, and just for Enterprise customers with backwards compatibility requirements ([docs][ip-cf])
- Fly.io: `fly-client-ip` - the socket ip address ([docs](https://www.fly.io/docs/networking/request-headers/#fly-client-ip))
- Azure FrontDoor: `x-azure-socketip` - the socket IP address associated with the TCP connection that the current request originated from ([docs][azure-frontdoor])
- nginx with correctly configured [`ngx_http_realip_module`](https://nginx.org/en/docs/http/ngx_http_realip_module.html) 
  * ⛔ do not use `proxy_set_header X-Real-IP $remote_addr;` 

**Provider headers that require extra config:**

These providers offer headers that out of the box are trivially spoofable, and require extra configuration (in your provider's management interface) to configure securely.

- Akamai: `true-client-ip` -  do trivially spoofable by default, refer to [this writeup](https://adam-p.ca/blog/2022/03/x-forwarded-for/#akamai)
- Fastly: `fastly-client-ip` - trivially spoofable, you must use vcl to configure it [fastly docs](https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Client-IP/)

**⛔ Provider headers to avoid:**

In nearly all of these cases you are better of using XFF and reasoning about the number of proxies or their network addresses.

- Azure FrontDoor: `x-azure-clientip` - trivially spoofable as it is the leftmost-ish XFF ([docs][azure-frontdoor])

[ip-cf]: https://developers.cloudflare.com/fundamentals/get-started/http-request-headers/
[azure-frontdoor]: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol

```clojure
;; Clients connect to your application server *only* through and *directly* through Cloudflare
(strategy/single-ip-header-strategy "cf-connecting-ip")

;; Clients connect to your application server *only* through and *directly* through Fly.io
(strategy/single-ip-header-strategy "fly-client-ip")
```

**Example networks:**
```
Client -> Cloudflare -> Your Server
Client -> nginx -> Your Server  
Client -> Load Balancer -> Your Server
```

**Security considerations:**

- Ensure the header cannot be spoofed by clients
- Verify clients cannot bypass your proxy
- Use only the header *your* trusted proxy sets

**⚠️ Common mistakes:**

- Using `x-forwarded-for` with this strategy (use rightmost strategies instead)
- Not validating that clients must go through your proxy
- Changes to your topology that break a rule that was previously true
    - For example, adding another proxy in the chain or exposing servers on a different interface
- Using headers that can be set by untrusted sources

---

### Rightmost Non-Private Strategy

**When to use:** You have multiple reverse proxies between the internet and the server, all using private IP addresses, and they append to `X-Forwarded-For` or `Forwarded` headers.

**Why:** In a typical private network setup, the rightmost non-private IP in the trusted forwarding chain is the real client IP. Private IPs represent your infrastructure.

```clojure
(strategy/rightmost-non-private-strategy "x-forwarded-for")

;; Using RFC 7239 Forwarded header
(strategy/rightmost-non-private-strategy "forwarded")
```

**Example networks:**
```
Client -> Internet Proxy -> Private Load Balancer -> Private App Server
         (1.2.3.4)      (10.0.1.1)            (10.0.2.1)

X-Forwarded-For: 1.2.3.4, 10.0.1.1
Result: 1.2.3.4 (rightmost non-private)
```

**Security:** Secure. Attackers can still spoof the leftmost entries, but not the rightmost non-private IP.

**⚠️ Common Mistakes:**

- Do not use when your proxies have public IP addresses
- Do not use when you need to trust specific proxy IPs (use trusted range strategy instead)

---

### Rightmost Trusted Count Strategy

**When to use:** You know exactly how many trusted proxies append IPs to the header, and you want the IP added by the first trusted proxy.

**Why:** When you have a fixed, known number of trusted proxies, counting backwards gives you the IP that was added by your first trusted proxy (the client IP it saw).

```clojure
;; Two trusted proxies
(strategy/rightmost-trusted-count-strategy "x-forwarded-for" 2)

;; One trusted proxy  
(strategy/rightmost-trusted-count-strategy "forwarded" 1)
```

**Example with count=2:**
```
Client -> Proxy1 -> Proxy2 -> Your Server
         (adds A)  (adds B)

X-Forwarded-For: A, B
With count=2: Skip 2 from right, return A
```

**Security:** Secure, when your proxy count is stable and known.

**⚠️ Common Mistakes:**

- Count must exactly match your trusted proxy count
- If the count is wrong, you'll get incorrect results or errors
- Network topology changes require updating the count on the application server

---

### Rightmost Trusted Range Strategy

**When to use:** You know the IPs ranges of all your trusted proxies and want the rightmost IP that's not from a trusted source.

**Why:** This is the most flexible strategy for complex infrastructures where you know your proxy IPs but they might change within known ranges.

```clojure

;; You have a VPC where your client-facing load balancer could be any ip address inside the 10.1.1.0/24 subnet (az1) or 10.1.2.0/24 (az2)
(strategy/rightmost-trusted-range-strategy 
  "x-forwarded-for"
  ["10.1.1.0/24" "10.1.2.0/24"])

;; Including Cloudflare ranges (these are examples, do not copy them!)
(strategy/rightmost-trusted-range-strategy
  "x-forwarded-for"  
  ["173.245.48.0/20" "103.21.244.0/22"   ; Example Cloudflare IPv4 ranges
   "2400:cb00::/32"])                    ; Example Cloudflare IPv6 range
```

**Example:**
```
Client -> Cloudflare -> Your Load Balancer -> App Server
  1.2.3.4   173.245.48.1      10.0.1.1

X-Forwarded-For: 1.2.3.4, 173.245.48.1, 10.0.1.1
Trusted ranges: ["173.245.48.0/20", "10.0.0.0/8"]
Result: 1.2.3.4 (rightmost IP not in trusted ranges)
```

**Security:** Secure, when ranges are properly maintained.

**⚠️ Common Mistakes:**

- Forgetting to keep the trusted ranges up to date
- Not include all possible proxy IPs
- When using a cloud provider, not using their API for current up to date ranges

---

### Chain Strategy

**When to use:** You have multiple possible network paths to your server and need fallback behavior.

**⚠️ Security warning:** 

Do not abuse ChainStrategy to check multiple headers. There is likely only one
header you should be checking, and checking more can leave you vulnerable to IP
spoofing.

Each strategy should represent a different network path, not multiple ways to
parse the same path.

**Why:** Real-world deployments can have multiple possible configurations (direct connections or via CDN). Chain strategy tries each approach until one succeeds.

```clojure

;; Clients can connect view cloudflare or directly to your server
(strategy/chain-strategy
  [(strategy/single-ip-header-strategy "cf-connecting-ip")
   (strategy/remote-addr-strategy)])

;; Multiple fallback levels
(strategy/chain-strategy
  [(strategy/rightmost-trusted-range-strategy  "x-forwarded-for"  ["10.0.0.0/8"])
   (strategy/rightmost-non-private-strategy "x-forwarded-for")  
   (strategy/remote-addr-strategy)])
```

**Example use cases:**
- Development vs production environments
- Gradual migration between proxy setups
- Handling both CDN and direct traffic

---

### Leftmost Non-Private Strategy

**⚠️ Security warning:** **DO NOT USE UNLESS YOU REALLY KNOW WHAT YOU ARE DOING.** The leftmost IP can be trivially spoofed by clients.

**When to use:** Rarely recommended. Only when you specifically need the IP allegedly closest to the original client (knowing full well that it can be spoofed).

**Why:** This gives you the "apparent" client IP but offers *no security* against spoofing.

```clojure
(strategy/leftmost-non-private-strategy "x-forwarded-for")

(strategy/leftmost-non-private-strategy "forwarded")
```

**Example:**
```
X-Forwarded-For: 1.2.3.4, 2.3.4.5, 192.168.1.1
Result: 1.2.3.4 (leftmost non-private)
```

**Valid use cases:**

- Debugging or logging where you want the "claimed" client IP
- Analytics where approximate location matters more than accuracy

## Testing Your Configuration

Before deploying features that rely on the client ip address, deploy this
middleware with logging into your production network and verify your strategy
works correctly:

1. **Test with expected traffic:** Ensure you get the right IP for normal requests
2. **Test spoofing attempts:** Verify that fake headers are ignored, you can spoof headers easily with `curl -H "X-Forwarded-For: 1.2.3.4" ...`
3. **Monitor for empty results:** The middleware returns `nil` when a failure occurs, this could indicate an attack or a configuration problem.

## Common Pitfalls

1. **Using multiple headers:** Never chain strategies that check different headers from the same request
2. **Wrong header choice:** For example, using `x-forwarded-for` when your proxy sets `x-real-ip`
3. **Ignoring network changes:** Proxy counts or ranges change but your app configuration doesn't
4. **Development vs production:** Different strategies needed for different environments
5. **Not validating proxy control:** Assuming headers can't be spoofed when they can, don't just trust the hyperscalers or commercial CDNs, *verify*.

Remember: **the right strategy depends entirely on your specific network configuration**. When in doubt, analyze real traffic in a real network setting.
