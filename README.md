# Lets Encrypt ACME Client

Automatically Issue and Renew `Let's Encrypt Certificates` (ACMEv2)

Utilizes a `Daemon` that operates periodically alongside a `Mixin` to handle challenge completions.

## Getting Started

You can view the full [`SSL Server Example`](https://github.com/FirstTimeEZ/server-ssl) to understand the `Daemon` and `Mixin`

### Daemon

The `Daemon` runs periodically to Issue or Renew the certificate

```javascript
/**
 * Starts the Let's Encrypt Daemon to Manage the SSL Certificate for the Server
 *
 * @param {Array<string>} fqdns - The fully qualified domain names as a SAN (e.g., ["example.com", "www.example.com"]).
 * @param {string} sslPath - The path where the public and private keys will be stored/loaded from.
 * @param {function} certificateCallback - Callback that can be used to update the certificates or trigger a restart etc.
 * @param {boolean} [optGenerateAnyway=false] - (optional) True to generate certificates before the 60 days has passed.
 * @param {boolean} [optStaging=false] - (optional) True to use staging mode instead of production.
 * 
 * @note
 * You can only start the daemon once for now.
 */
export async function startLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optGenerateAnyway = false, optStaging = false)
```

### HTTP Mixin

`HTTP Mixin` that completes the `HTTP-01` Challenges created by the `Daemon`

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