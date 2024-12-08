# Lets Encrypt ACME Client

Uses a `Daemon` and a `Mixin` to issue and renew `Lets Encrypt!` certificates automatically (ACMEv2)

## Getting Started

The easiest way to understand how the daemon and mixin work is to view the full [`Node.js SSL Server Example`](https://github.com/FirstTimeEZ/server-ssl)

### Daemon

```javascript
/**
 * Starts the Let's Encrypt daemon to manage SSL certificates.
 *
 * @param {array} fqdns - The fully qualified domain name as a SAN ["example.com","www.example.com"]
 * @param {string} sslPath - The path where the public and private keys will be stored/loaded from.
 * @param {boolean} daysRemaining - The number of days left before the certificate expires
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

`HTTP` mixin that completes the `HTTP-01` Challenges

```javascript
/**
 * Node.js Middleware function to check and respond to ACME HTTP-01 challenges inside the HTTP Server.
 *
 * @example
 * createServerHTTP((req, res) => { if (checkChallengesMixin(req, res)) { return; } }).listen(80);
 */
export async function checkChallengesMixin(req, res)
```