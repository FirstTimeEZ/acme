# LetsEncrypt! ACME Client

Automatically Create and Renew `LetsEncrypt! SSL Certificates`, including `Wildcard Certificates` for supported `DNS Providers`

### Getting Started

This most recent version of this package is implemented in [`SSL Server`](https://github.com/FirstTimeEZ/server-ssl) and you can use that to understand how it works if the `jsdoc` isn't enough information.

### Wild Card Certificates

You can generate `Wild Card Certificates` if you are using a supported `DNS Provider`

| Supported DNS Providers |
|-------------------------|
| Cloud Flare  |

```
let dnsProvider = {
    name: "Cloud Flare",
    token: "apiTokenWithDnsEditPermission",
    zone: "zoneId" // optional if it cant be found automatically.
}
```

`DNS Providers` are used to complete `DNS-01` challenges

--------

### LetsEncrypt! Daemon

The `Daemon` runs periodically to `Create` or `Renew` the `Certificate`

```javascript
/**
 * Starts the LetsEncrypt! Daemon to Manage the SSL Certificate for the Server
 *
 * @param {Array<string>} fqdns - The fully qualified domain names as a SAN (e.g., ["example.com", "www.example.com"]), You must use a `dnsProvider` if you include a wild card
 * @param {string} sslPath - The path where your acme account, keys and generated certificate will be stored or loaded from
 * @param {function} certificateCallback - Callback that can be used to update the current certificate or trigger a restart etc.
 * @param {boolean} [optGenerateAnyway=false] - (optional) True to generate a new certificate before the recommended time.
 * @param {boolean} [optStaging=false] - (optional) True to use staging mode instead of production.
 * 
 * @param {Object} dnsProvider - (optional) credentials for a supported dns provider if you want to use the `DNS-01` Challenge instead of `HTTP-01`
 * @example
 * const dnsProvider = {
 *     name: "Cloud Flare",
 *     token: "dnsEditPermissionApiToken",
 *   //zone: "zoneId", // if it cant be found automatically
 * }
 * @note
 * If you start this more than once nothing will happen
 */
export async function startLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optGenerateAnyway = false, optStaging = false, dnsProvider = undefined)
```

### HTTP Mixin for `HTTP-01`

`HTTP Mixin` that completes the `HTTP-01` Challenges created by the `Daemon`

This is not required if you are using a `DNS Provider`

```javascript
/**
 * Node.js Middleware function to check and respond to ACME HTTP-01 challenges inside the HTTP Server.
 *
 * @example
 * createServerHTTP(async (req, res) => {
 *     if (STATE.optLetsEncrypt && await checkChallengesMixin(req, res)) { return; } 
 *     // normal request redirect etc
 * }).listen(80);
 */
export async function checkChallengesMixin(req, res)
```

--------

### Challenges

The `DNS-01` and `HTTP-01` challenges have been implemented