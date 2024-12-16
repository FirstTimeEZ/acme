/**
 * Copyright © 2024 FirstTimeEZ
 * https://github.com/FirstTimeEZ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as asn1 from 'simple-asn1';
import * as acme from 'base-acme-client';
import { join } from 'path';
import { generateKeyPairSync } from 'crypto';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';

const packageJson = await import('./package.json', { with: { type: 'json' } });

const DIRECTORY_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
const DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
const WELL_KNOWN = "/.well-known/acme-challenge/";
const ACME_CHALLENGE = "HTTP-01 ACME Challenge";
const CONTENT_TYPE = "Content-Type";
const STATUS_PENDING = "pending";
const HTTP = "http-01";
const DELIM = "/";

const LAST_CERT_FILE = "last_certification.ez";

const ARRAY = 1;
const SUCCESS = 200;
const EXPECTED_SPLITS = 4;
const MAX_LENGTH = 1000;
const MIN_LENGTH = 32;

const PUBLIC_KEY = '/acmePublicKey.raw';
const PRIVATE_KEY = '/acmePrivateKey.raw';
const PUBLIC_KEY_SIGN = '/acmePublicSignKey.raw';
const PRIVATE_KEY_SIGN = '/acmePrivateSignKey.raw';

const CONTENT_TYPE_OCTET = 'application/octet-stream';

const VALID = "valid";

const REDIRECT_ONLY = "Cleared Answered Challenges - HTTP is now redirect only until new challenges are created";

const ONE_SECOND_MS = 1000;
const CHECK_CLOSE_TIME = 65000;

let pendingChallenges = [];

let checkAnswersFlag = false;
let localHost = false;
let checkedForLocalHost = false;

let acmeKeyChain = undefined;

let jsonWebKey = undefined;
let jsonWebKeyThumbPrint = null;

let acmeDirectory = null;
let acmeDirectoryURL = DIRECTORY_PRODUCTION;

let daemonI = null;
let ariWindow = null;

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
 * 
 * @note
 * You can only start the daemon once for now
 */
export async function startLetsEncryptDaemon(fqdns, sslPath, daysRemaining, certificateCallback, optGenerateAnyway, optStaging, optAutoRestart, countdownHandler, countdownTime) {
    if (daemonI === null) {
        const randTime = Math.floor(Math.random() * (12300000 - 1000000 + 1)) + 1000000;

        optStaging === true && (acmeDirectoryURL = DIRECTORY_STAGING, console.log("USING THE STAGING SERVER"));

        const daemon = async () => {
            try {
                console.log("Starting Lets Encrypt ACME Daemon!", "v" + packageJson.default.version);
                console.log("Copyright © 2024 " + packageJson.default.author);
                console.log("--------");

                if (await internalUpdateDirectory()) {
                    return;
                }

                console.log("Determining if its time to issue a new SSL Certificate");

                await internalFetchSuggest(sslPath, acmeDirectory);

                if (internalDetermineRequirement(fqdns, sslPath, daysRemaining, optStaging) && optGenerateAnyway !== true) {
                    return;
                }

                await internalGetAcmeKeyChain(sslPath);

                for (let index = 0; index <= 3; index++) {
                    try {
                        const success = await internalLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optAutoRestart, countdownHandler, countdownTime, optStaging);

                        if (success === true) {
                            console.log("Completed Successfully", index + 1);
                            return;
                        }
                        else {
                            index + 1 <= 3 && console.log("Something went wrong, trying again", index + 1);
                        }
                    } catch {
                        console.error("Something went wrong, trying again", index + 1);
                    }
                }

                console.error("------------------");
                console.error("Something is preventing the Lets Encrypt Daemon");
                console.error("from creating or renewing your certificate");
                console.error("------------------");
            } catch (exception) {
                console.log(exception);
            }
        };

        daemon();

        daemonI = setInterval(daemon, 33200000 + randTime);
    }
}

/**
 * Node.js Middleware function to check and respond to ACME HTTP-01 challenges inside the HTTP Server.
 *
 * @example
 * createServerHTTP(async (req, res) => {
 *     if (STATE.optLetsEncrypt && await checkChallengesMixin(req, res)) { return; } 
 *     // normal request redirect etc
 * }).listen(80);
 */
export async function checkChallengesMixin(req, res) {
    if (pendingChallenges.length === 0 || localHost === true || jsonWebKeyThumbPrint == undefined || internalCheckChallenges()) {
        return false;
    }

    try {
        if (internalCheckForLocalHostOnce(req)) {
            return false;
        }

        if (req.url.startsWith(WELL_KNOWN) && req.url.length < MAX_LENGTH) {
            const split = req.url.split(DELIM);

            if (split.length === EXPECTED_SPLITS) {
                const token = split[split.length - ARRAY];

                if (token.length > MIN_LENGTH) {
                    let bufferModified = false;

                    for (let index = 0; index < pendingChallenges.length; index++) {
                        const challenge = pendingChallenges[index];

                        if (challenge.type == HTTP && challenge.token == token) {
                            console.log(ACME_CHALLENGE, challenge.token);

                            res.writeHead(SUCCESS, { [CONTENT_TYPE]: CONTENT_TYPE_OCTET });
                            res.end(Buffer.from(`${challenge.token}.${jsonWebKeyThumbPrint}`));

                            bufferModified = true;

                            checkAnswersFlag === false && (checkAnswersFlag = true, setTimeout(async () => await internalCheckAnswered(), CHECK_CLOSE_TIME));
                        }
                    }

                    return bufferModified;
                }
            }
        }
    } catch { } // Ignore

    return false;
}

function internalCheckForLocalHostOnce(req) {
    if (checkedForLocalHost === false && localHost === false) {
        checkedForLocalHost = true;

        let ip = req.socket.remoteAddress;

        if (req.headers['x-forwarded-for']) {
            ip = req.headers['x-forwarded-for'].split(',')[0];
        }

        if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
            localHost = true;
            console.error(ip, req.headers.host, "You can not generate lets encrypt certificates for localhost");

            return true;
        }
    }

    return false;
}

function internalDetermineRequirement(fqdns, certFilePath, daysRemaining, optStaging) {
    const certFile = join(certFilePath, LAST_CERT_FILE);
    let ok = false;

    if (existsSync(certFile)) {
        const identifierBased = readFileSync(certFile);

        if (identifierBased != undefined) {
            const lastIdentifiers = JSON.parse(identifierBased);

            if (lastIdentifiers != undefined) {
                lastIdentifiers.time != undefined && console.log("It has been: " + ((Date.now() - lastIdentifiers.time) / ONE_SECOND_MS) + " seconds since you last generated certificates");

                if (lastIdentifiers.names instanceof Array) {
                    if (fqdns.length !== lastIdentifiers.names.length) {
                        return ok;
                    }

                    if (lastIdentifiers.staging !== optStaging) {
                        console.log("The certificate you were using was generated for a different configuration");
                        return ok;
                    }

                    for (let index = 0; index < lastIdentifiers.names.length; index++) {
                        if (fqdns[index] != lastIdentifiers.names[index]) {
                            return ok;
                        }
                    }
                }
            }
        }

        if (ariWindow != undefined) {
            const nowUtc = new Date().getTime();
            const startT = new Date(ariWindow.start).getTime();
            const endT = new Date(ariWindow.end).getTime();

            if (startT > nowUtc && endT > nowUtc) {
                console.log("Automated Renewal Information Window", ariWindow);
                ok = true;
            }
            else if (startT < nowUtc && endT > nowUtc) {
                ok = false;
                console.log("Inside Renewal Window - Generating Certificates", ariWindow);
            }
            else {
                console.log("Outside Renewal Window - Generating Certificates", ariWindow);
                ok = false;
            }
        }

        //todo: rework/re-add daysRemaining based window
    }

    return ok;
}

function internalCheckChallenges() {
    for (let index = 0; index < pendingChallenges.length; index++) {
        if (pendingChallenges[index].answered === false) {
            return false;
        }
    }

    if (pendingChallenges.length > 0) {
        pendingChallenges = [];
        console.log(REDIRECT_ONLY);
    }

    return true;
}

async function internalUpdateDirectory() {
    const dir = await acme.newDirectory(acmeDirectoryURL);

    if (dir.answer.directory != undefined) {
        acmeDirectory = dir.answer.directory;
    }
    else {
        if (acmeDirectory === null) {
            console.error("Error getting directory first time", dir.answer.error);

            const dir = await acme.newDirectory(acmeDirectoryURL);

            if (dir.answer.directory != undefined) {
                acmeDirectory = dir.answer.directory;
            }
            else {
                console.error("Failed to get directory after multiple attempts, trying again later");

                return true;
            }
        }
        else {
            console.log("Error updating directory, trying to use the old copy", dir.answer.error);
        }
    }

    return false;
}

async function internalCheckAnswered() {
    checkAnswersFlag = false;

    try {
        for (let index = 0; index < pendingChallenges.length; index++) {
            const element = pendingChallenges[index];

            if (pendingChallenges[index].answered === false) {
                const response = await acme.fetchAndRetryUntilOk(element.url);

                if (response && response.ok) {
                    const record = await response.json();

                    if (record.status === VALID) {
                        // console.log("HTTP-01 ACME Challenge Token", record.token);

                        pendingChallenges[index].answered = true;
                    }
                    else if (record.status === 404) {
                        pendingChallenges[index].answered = true;
                    }
                }
            }
        }

        internalCheckChallenges();
    } catch (exception) {
        console.error(exception);
    }
}

async function internalGetAcmeKeyChain(sslPath) {
    if (acmeKeyChain === undefined) {
        acmeKeyChain = {};

        if (existsSync(sslPath + PUBLIC_KEY) && existsSync(sslPath + PRIVATE_KEY)) {
            acmeKeyChain.publicKeyRaw = readFileSync(sslPath + PUBLIC_KEY);
            acmeKeyChain.privateKeyRaw = readFileSync(sslPath + PRIVATE_KEY);
            acmeKeyChain.publicKey = acme.formatPublicKey(acmeKeyChain.publicKeyRaw.toString());
            acmeKeyChain.privateKey = acme.formatPrivateKey(acmeKeyChain.privateKeyRaw.toString());

            console.log("Load ACME Keys From File");

            if (existsSync(sslPath + PUBLIC_KEY_SIGN) && existsSync(sslPath + PRIVATE_KEY_SIGN)) {
                acmeKeyChain.publicKeySignRaw = readFileSync(sslPath + PUBLIC_KEY_SIGN);
                acmeKeyChain.privateKeySignRaw = readFileSync(sslPath + PRIVATE_KEY_SIGN);
                acmeKeyChain.publicKeySign = acme.formatPublicKey(acmeKeyChain.publicKeySignRaw.toString());
                acmeKeyChain.privateKeySign = acme.formatPrivateKey(acmeKeyChain.privateKeySignRaw.toString());

                console.log("Load Signing Keys From File");
            }
        }
        else {
            console.log("Creating a Key Chain to use for ACME Challenges and CSRs");

            mkdirSync(sslPath, { recursive: true });

            if (true) { // Acme Keys
                const { publicKey, privateKey, } = generateKeyPairSync('ec', { namedCurve: 'P-256', extractable: true });

                acmeKeyChain.publicKey = publicKey;
                acmeKeyChain.privateKey = privateKey;

                acmeKeyChain.publicKeyRaw = publicKey.export({ format: 'pem', type: 'spki' });
                acmeKeyChain.privateKeyRaw = privateKey.export({ format: 'pem', type: 'pkcs8' });

                writeFileSync(sslPath + PUBLIC_KEY, acmeKeyChain.publicKeyRaw);
                writeFileSync(sslPath + PRIVATE_KEY, acmeKeyChain.privateKeyRaw);

                console.log('ACME Keys saved to File');
            }

            if (true) { // Signing Keys
                const { publicKey, privateKey, } = generateKeyPairSync('ec', { namedCurve: 'P-256', extractable: true });

                acmeKeyChain.publicKeySign = publicKey;
                acmeKeyChain.privateKeySign = privateKey;

                acmeKeyChain.publicKeySignRaw = publicKey.export({ format: 'pem', type: 'spki' });
                acmeKeyChain.privateKeySignRaw = privateKey.export({ format: 'pem', type: 'pkcs8' });

                writeFileSync(sslPath + PUBLIC_KEY_SIGN, acmeKeyChain.publicKeySignRaw);
                writeFileSync(sslPath + PRIVATE_KEY_SIGN, acmeKeyChain.privateKeySignRaw);

                console.log('Signing Keys saved to File');
            }
        }

        if (jsonWebKey == undefined) {
            const jwk = await acme.createJsonWebKey(acmeKeyChain.publicKey);
            jsonWebKey = jwk.key;
            jsonWebKeyThumbPrint = jwk.print;
        }
    }
}

async function internalLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optAutoRestart, countdownHandler, countdownTime, optStaging) {
    let domains = [];
    let account = undefined;
    let nextNonce = undefined;
    let firstNonce = undefined;
    let authorizations = undefined;

    countdownHandler != undefined && (countdownTime == undefined || countdownTime < 30) && (countdownTime = 30);

    firstNonce = await acme.newNonce(acmeDirectory.newNonce);

    if (firstNonce.nonce == undefined) {
        console.error("Error getting nonce", firstNonce.answer.error);
        return false;
    }

    account = await acme.createAccount(firstNonce.nonce, acmeKeyChain.privateKey, jsonWebKey, acmeDirectory).catch(console.error);

    if (account.answer.account == undefined || account.answer.account.status != VALID) {
        console.error("Error creating account", account.answer.error);
        return false;
    }

    fqdns.forEach((element) => domains.push({ "type": "dns", "value": element }));

    const order = await acme.createOrder(account.answer.location, account.nonce, acmeKeyChain.privateKey, domains, acmeDirectory);

    if (order.answer.order == undefined) {
        console.error("Error getting order", order.answer.error);
        return false;
    }

    console.log("Next Nonce", (nextNonce = order.nonce));

    authorizations = order.answer.order.authorizations;

    for (let index = 0; index < authorizations.length; index++) {
        const auth = await acme.postAsGet(account.answer.location, nextNonce, acmeKeyChain.privateKey, authorizations[index], acmeDirectory);

        if (auth.answer.get.status) {
            for (let index = 0; index < auth.answer.get.challenges.length; index++) {
                const challenge = auth.answer.get.challenges[index];
                challenge.type == HTTP && (challenge.answered = false, pendingChallenges.push(challenge));
            }

            console.log("Next Nonce", (nextNonce = auth.nonce));
        } else {
            console.error("Error getting auth", auth.answer.error);
        }
    }

    for (let index = 0; index < pendingChallenges.length; index++) {
        if (pendingChallenges[index].type == HTTP && pendingChallenges[index].status == STATUS_PENDING) {
            const auth = await acme.postAsGetChal(account.answer.location, nextNonce, acmeKeyChain.privateKey, pendingChallenges[index].url, acmeDirectory);
            auth.answer.get.status ? console.log("Next Nonce", (nextNonce = auth.nonce), "Authed Challenge") : console.error("Error getting auth", auth.answer.error);
        }
    }

    return await new Promise(async (resolve) => {
        let finalizedCertificateLocation = null;
        let finalizedLocation = null;
        let finalizedInfo = null;

        await new Promise(async (resolve) => {
            const waitForReady = setInterval(async () => {
                await acme.postAsGet(account.answer.location, nextNonce, acmeKeyChain.privateKey, order.answer.location, acmeDirectory).then((order) => {
                    nextNonce = order.nonce;

                    if (order.answer.get != undefined && order.answer.get.status == "ready") {
                        finalizedInfo = order.answer.get.finalize;
                        console.log("Ready to Finalize", fqdns);
                        clearInterval(waitForReady);
                        resolve();
                    }
                });
            }, 1500);
        });

        await new Promise(async (resolve) => {
            const waitForFinalize = setInterval(async () => {
                await acme.finalizeOrder(fqdns[0], account.answer.location, nextNonce, acmeKeyChain.privateKey, acmeKeyChain.publicKeySign, acmeKeyChain.privateKeySign, finalizedInfo, fqdns, acmeDirectory).then((finalized) => {
                    if (finalized.answer.get) {
                        if (finalized.answer.get.status == "processing" || finalized.answer.get.status == VALID) {
                            finalizedLocation = finalized.answer.location;
                            console.log("Certificate Location", finalizedLocation);
                            clearInterval(waitForFinalize);
                            resolve();
                        }
                    }
                    else {
                        console.error("Error getting order", finalized.answer.error);
                    }

                    console.log("Next Nonce", (nextNonce = finalized.nonce));
                });
            }, 1500);
        });

        console.log("Waiting for Certificate to be Ready for Download");

        await new Promise(async (resolve) => {
            const waitForProcessingValid = setInterval(async () => {
                await acme.postAsGet(account.answer.location, nextNonce, acmeKeyChain.privateKey, finalizedLocation, acmeDirectory).then((checkFinalized) => {
                    if (checkFinalized.answer.get != undefined && checkFinalized.answer.get.status == VALID) {
                        finalizedCertificateLocation = checkFinalized.answer.get.certificate;
                        console.log("Certificate URL:", finalizedCertificateLocation);
                        clearInterval(waitForProcessingValid);
                        resolve();
                    }

                    console.log("Next Nonce", (nextNonce = checkFinalized.nonce));
                });
            }, 1500);
        });

        const response = await acme.fetchAndRetryUntilOk(finalizedCertificateLocation);

        if (response && response.ok) {
            const certificateText = await response.text();

            if (checkCertificateTextValid(certificateText) && checkPrivateKeyValid(acmeKeyChain.privateKeySignRaw.toString())) {
                console.log("Certificate Downloaded, Saving to file");

                writeFileSync(join(sslPath, "certificate.pem"), certificateText);

                writeFileSync(join(sslPath, "private-key.pem"), acmeKeyChain.privateKeySignRaw);

                writeFileSync(join(sslPath, LAST_CERT_FILE), JSON.stringify({ time: Date.now(), names: fqdns, staging: optStaging }));

                setTimeout(async () => { console.log(await internalUpdateSuggestFromText(certificateText, acmeDirectory)); }, 5000);

                if (optAutoRestart === true) {
                    console.log("-------");
                    console.log("Auto Restart is Enabled");
                    console.log("Restarting Server when ready...");
                    console.log("-------");

                    if (countdownHandler == undefined) {
                        process.exit(123); // Resolved by exit
                    }
                    else {
                        let count = 0;
                        setInterval(() => (count++, count > countdownTime ? process.exit(123) : countdownHandler()), 1000); // Resolved by exit
                    }
                }
                else if (certificateCallback != undefined) {
                    await new Promise((resolve) => {
                        const certI = setInterval(() => {
                            certificateCallback();
                            internalCheckAnswered();
                            clearInterval(certI);
                            resolve();
                        }, 200);
                    });
                }

                resolve(true);
            }
            else {
                console.error("Something went wrong generating the certificate or the private key, will try again at the usual time");
            }
        } else {
            console.error("Something went wrong fetching the certificate, will try again at the usual time"); // todo: try again sooner / check time
        }

        resolve(false);
    });
}

async function internalFetchSuggest(sslPath, acmeDirectory) {
    const path = join(sslPath, "certificate.pem");

    existsSync(path) && await internalUpdateSuggestFromText(readFileSync(path, "utf8"), acmeDirectory);
}

async function internalUpdateSuggestFromText(certificateText, acmeDirectory) {
    try {
        const certPem = asn1.pemToBuffer(certificateText);

        if (certPem != null) {
            const a = await asn1.decodeAKI(certPem);
            const s = await asn1.decodeSerialNumber(certPem);

            if (a == undefined || s == undefined) {
                return undefined;
            }

            const window = await acme.fetchSuggestedWindow(acmeDirectory.renewalInfo, a, s);

            window.answer.get != undefined && (ariWindow = window.answer.get.suggestedWindow);

            return ariWindow;
        }
        else {
            console.error("Certificate was null, you should report this as an issue");
        }
    } catch (exception) {
        console.error(exception);
    }
}

function checkCertificateTextValid(certificateText) {
    return certificateText.startsWith("-----BEGIN CERTIFICATE-----") && (certificateText.endsWith("-----END CERTIFICATE-----\n") || certificateText.endsWith("-----END CERTIFICATE-----") || certificateText.endsWith("-----END CERTIFICATE----- "));
}

function checkPrivateKeyValid(privateKey) {
    return privateKey.startsWith("-----BEGIN PRIVATE KEY-----") && (privateKey.endsWith("-----END PRIVATE KEY-----") || privateKey.endsWith("-----END PRIVATE KEY-----\n") || privateKey.endsWith("-----END PRIVATE KEY----- "))
}