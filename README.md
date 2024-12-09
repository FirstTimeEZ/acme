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
 * @param {array} fqdns - The fully qualified domain name as a SAN ["example.com","www.example.com"]
 * @param {string} sslPath - The path where the public and private keys will be stored/loaded from.
 * @param {boolean} daysRemaining - The number of days left before the certificate expires; remember to reset this in the certificateCallback (currently to 89)
 * @param {function} certificateCallback - callback that can be used to update the certificates if auto restart is disabled
 * @param {boolean} optGenerateAnyway - (optional) True to generate certificates before the 60 days has passed
 * @param {boolean} optStaging - (optional) True to use staging mode instead of production
 * @param {boolean} optAutoRestart - (optional) True to restart after certificates are generated, You don't need to do this but you might want to
 * @param {function} countdownHandler - (optional) paramterless function that will fire every second during the restart count down
 * @param {function} countdownTime - (optional) how long in seconds to countdown before restarting, default 30 seconds
 */
export async function startLetsEncryptDaemon(fqdns, sslPath, daysRemaining, certificateCallback, optGenerateAnyway, optStaging, optAutoRestart, countdownHandler, countdownTime)
```

### HTTP Mixin

`HTTP Mixin` that completes the `HTTP-01` Challenges created by the `Daemon`

```javascript
/**
 * Node.js Middleware function to check and respond to ACME HTTP-01 challenges inside the HTTP Server.
 *
 * @example
 * createServerHTTP((req, res) => { if (checkChallengesMixin(req, res)) { return; } }).listen(80);
 */
export async function checkChallengesMixin(req, res)
```