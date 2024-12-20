# LetsEncrypt! ACME Client

Automatically Create and Renew `LetsEncrypt! SSL Certificates`, including `Wildcard Certificates` for supported `DNS Providers`

### Getting Started

```javascript
import LetsEncryptDaemon from 'lets-encrypt-acme-client';
```

#### Simple Usage Example

Create a `LetsEncryptDaemon` and then start the `Daemon`

```javascript
const daemon = new LetsEncryptDaemon();
daemon.startLetsEncryptDaemon(...); // You can only start this once, it will configure itself to run again.
daemon.checkChallengesMixin(...); // You must check the HTTP-01 Challenges for each LetsEncryptDaemon
```

#### Complete Example Usage

This most recent version of this package is implemented in [`SSL Server`](https://github.com/FirstTimeEZ/server-ssl) 

You can use [`SSL Server`](https://github.com/FirstTimeEZ/server-ssl) to understand how it works if the `jsdoc` isn't enough information.

--------

### Wild Card Certificates

| Supported DNS Providers |
|-------------------------|
| Cloud Flare  |

You can generate `Wild Card Certificates` if you are using a supported `DNS Provider`

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

`LetsEncryptDaemon` is the default exported class

### Daemon

The `Daemon` runs periodically to `Create` or `Renew` the `Certificate`

```javascript
/**
 * Starts the LetsEncrypt! Daemon to Manage a SSL Certificate
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
 * Node.js Middleware function to check and respond to ACME HTTP-01 challenges issued by this LetsEncryptDaemon inside the HTTP Server.
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