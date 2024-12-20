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
import * as util from './ext/ext.js';
import Promised from './ext/promised.js';
import { join } from 'path';
import { runCommandSync } from 'simple-open-ssl';
import { createHash, generateKeyPairSync } from 'crypto';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { CF_Provider, extractZoneName } from './providers/cloudflare.js';

const packageJson = await import('./package.json', { with: { type: 'json' } });

const DIRECTORY_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
const DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
const WELL_KNOWN = "/.well-known/acme-challenge/";
const ACME_CHALLENGE = "HTTP-01 ACME Challenge";
const CONTENT_TYPE = "Content-Type";
const STATUS_PENDING = "pending";
const DELIM = "/";

const DNS = "dns-01";
const HTTP = "http-01";

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

/**
 * Create an `LetsEncrypt! Daemon` to Manage a `SSL Certificate`
 * 
 * @see startLetsEncryptDaemon - The actual daemon that will run periodcally after being started to create/renew certificates
 * @see checkChallengesMixin - You must check the `HTTP-01` challenges for each daemon you create
 * @remark `internal` methods could change at any time
 **/
export default class LetsEncryptDaemon {
    constructor() {
        this.challengeLists = [];
        this.httpChallenges = [];
        this.checkAnswersFlag = false;
        this.localHost = false;
        this.checkedForLocalHost = false;
        this.acmeKeyChain = undefined;
        this.jsonWebKey = undefined;
        this.jsonWebKeyThumbPrint = undefined;
        this.acmeDirectory = null;
        this.acmeDirectoryURL = DIRECTORY_PRODUCTION;
        this.one = false;
        this.ariWindow = null;
        this.remaining = { days: null, hours: null, minutes: null };
    }

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
    async startLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optGenerateAnyway = false, optStaging = false, dnsProvider = undefined) {
        if (this.one === true) {
            return;
        }

        this.one = true;

        let wcFlag = fqdns.some(v => v.startsWith("*."));

        if (wcFlag && !dnsProvider) {
            console.log("You can't create a wildcard certificate because there is no DNS Provider");
            return false;
        }

        if (wcFlag && dnsProvider) {
            const wcd = fqdns.find(v => v.startsWith("*."));

            const split = wcd.split(".");

            if (split.length >= 3) {
                fqdns = [extractZoneName(split), wcd]
            }
        }

        optStaging === true && (this.acmeDirectoryURL = DIRECTORY_STAGING, console.log("USING THE STAGING SERVER"));

        const daemon = async () => {
            try {
                console.log("Starting Lets Encrypt ACME Daemon!", "v" + packageJson.default.version);
                console.log("Copyright © 2024 " + packageJson.default.author);
                console.log("--------");

                if (await this.internalUpdateDirectory()) {
                    return;
                }

                console.log("Determining if its time to issue a new SSL Certificate");

                await this.internalFetchSuggest(sslPath, this.acmeDirectory);

                if (this.internalDetermineRequirement(fqdns, sslPath, optStaging) && optGenerateAnyway !== true) {
                    return;
                }

                await this.internalGetAcmeKeyChain(sslPath);

                for (let index = 0; index <= 3; index++) {
                    try {
                        const success = await this.internalLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optStaging, dnsProvider);

                        if (success === true) {
                            console.log("Daemon Completed Successfully", index + 1);
                            return;
                        }
                        else {
                            index + 1 <= 3 && console.log("Something went wrong, trying again", index + 1);
                        }
                    } catch (exception) {
                        console.error("Something went wrong, trying again", index + 1, exception);
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

        await daemon();

        const time = 33200000 + (Math.floor(Math.random() * (12300000 - 1000000 + 1)) + 1000000);

        console.log(`Configuring Daemon to run again after [${time}] milliseconds`);

        setInterval(daemon, time);
    }

    /**
     * Node.js Middleware function to check and respond to ACME HTTP-01 challenges issued by this LetsEncryptDaemon inside the HTTP Server.
     *
     * @example
     * createServerHTTP(async (req, res) => {
     *     if (STATE.optLetsEncrypt && await checkChallengesMixin(req, res)) { return; } 
     *     // normal request redirect etc
     * }).listen(80);
     */
    checkChallengesMixin(req, res) {
        if (this.httpChallenges.length === 0 || this.localHost === true || this.jsonWebKeyThumbPrint == undefined || this.internalCheckChallenges()) {
            return false;
        }

        try {
            if (this.internalCheckForLocalHostOnce(req)) {
                return false;
            }

            if (req.url.startsWith(WELL_KNOWN) && req.url.length < MAX_LENGTH) {
                const split = req.url.split(DELIM);

                if (split.length === EXPECTED_SPLITS) {
                    const token = split[split.length - ARRAY];

                    if (token.length > MIN_LENGTH) {
                        let bufferModified = false;

                        for (let index = 0; index < this.httpChallenges.length; index++) {
                            const challenge = this.httpChallenges[index];

                            if (challenge.type == HTTP && challenge.token == token) {
                                console.log(ACME_CHALLENGE, challenge.token);

                                res.writeHead(SUCCESS, { [CONTENT_TYPE]: CONTENT_TYPE_OCTET });
                                res.end(Buffer.from(`${challenge.token}.${this.jsonWebKeyThumbPrint}`));

                                bufferModified = true;

                                this.checkAnswersFlag === false && (this.checkAnswersFlag = true, setTimeout(async () => await this.internalCheckAnswered(), CHECK_CLOSE_TIME));
                            }
                        }

                        return bufferModified;
                    }
                }
            }
        } catch { } // Ignore

        return false;
    }

    async internalUpdateDirectory() {
        const dir = await acme.newDirectory(this.acmeDirectoryURL);

        if (dir.get != undefined) {
            this.acmeDirectory = dir.get;
        }
        else {
            if (this.acmeDirectory === null) {
                console.error("Error getting directory first time", dir.error);

                const dir = await acme.newDirectory(this.acmeDirectoryURL);

                if (dir.get != undefined) {
                    this.acmeDirectory = dir.get;
                }
                else {
                    console.error("Failed to get directory after multiple attempts, trying again later");

                    return true;
                }
            }
            else {
                console.log("Error updating directory, trying to use the old copy", dir.error);
            }
        }

        return false;
    }

    async internalCheckAnswered() {
        this.checkAnswersFlag = false;

        try {
            for (let index = 0; index < this.httpChallenges.length; index++) {
                const element = this.httpChallenges[index];

                if (this.httpChallenges[index].answered === false) {
                    const response = await acme.fetchAndRetryUntilOk(element.url);

                    if (response && response.ok) {
                        const record = await response.json();

                        if (record.status === VALID) {
                            this.httpChallenges[index].answered = true;
                        }
                        else if (record.status === 404) {
                            this.httpChallenges[index].answered = true;
                        }
                    }
                }
            }

            this.internalCheckChallenges();
        } catch (exception) {
            console.error(exception);
        }
    }

    async internalGetAcmeKeyChain(sslPath) {
        if (this.acmeKeyChain === undefined) {
            this.acmeKeyChain = {};

            if (existsSync(sslPath + PUBLIC_KEY) && existsSync(sslPath + PRIVATE_KEY)) {
                this.acmeKeyChain.publicKeyRaw = readFileSync(sslPath + PUBLIC_KEY);
                this.acmeKeyChain.privateKeyRaw = readFileSync(sslPath + PRIVATE_KEY);
                this.acmeKeyChain.publicKey = acme.formatPublicKey(this.acmeKeyChain.publicKeyRaw.toString());
                this.acmeKeyChain.privateKey = acme.formatPrivateKey(this.acmeKeyChain.privateKeyRaw.toString());

                console.log("Load ACME Keys From File");

                if (existsSync(sslPath + PUBLIC_KEY_SIGN) && existsSync(sslPath + PRIVATE_KEY_SIGN)) {
                    this.acmeKeyChain.publicKeySignRaw = readFileSync(sslPath + PUBLIC_KEY_SIGN);
                    this.acmeKeyChain.privateKeySignRaw = readFileSync(sslPath + PRIVATE_KEY_SIGN);
                    this.acmeKeyChain.publicKeySign = acme.formatPublicKey(this.acmeKeyChain.publicKeySignRaw.toString());
                    this.acmeKeyChain.privateKeySign = acme.formatPrivateKey(this.acmeKeyChain.privateKeySignRaw.toString());

                    console.log("Load Signing Keys From File");
                }
            }
            else {
                console.log("Creating a Key Chain to use for ACME Challenges and CSRs");

                mkdirSync(sslPath, { recursive: true });

                if (true) { // Acme Keys
                    const { publicKey, privateKey, } = generateKeyPairSync('ec', { namedCurve: 'P-256', extractable: true });

                    this.acmeKeyChain.publicKey = publicKey;
                    this.acmeKeyChain.privateKey = privateKey;

                    this.acmeKeyChain.publicKeyRaw = publicKey.export({ format: 'pem', type: 'spki' });
                    this.acmeKeyChain.privateKeyRaw = privateKey.export({ format: 'pem', type: 'pkcs8' });

                    writeFileSync(sslPath + PUBLIC_KEY, this.acmeKeyChain.publicKeyRaw);
                    writeFileSync(sslPath + PRIVATE_KEY, this.acmeKeyChain.privateKeyRaw);

                    console.log('ACME Keys saved to File');
                }

                if (true) { // Signing Keys
                    const { publicKey, privateKey, } = generateKeyPairSync('ec', { namedCurve: 'P-256', extractable: true });

                    this.acmeKeyChain.publicKeySign = publicKey;
                    this.acmeKeyChain.privateKeySign = privateKey;

                    this.acmeKeyChain.publicKeySignRaw = publicKey.export({ format: 'pem', type: 'spki' });
                    this.acmeKeyChain.privateKeySignRaw = privateKey.export({ format: 'pem', type: 'pkcs8' });

                    writeFileSync(sslPath + PUBLIC_KEY_SIGN, this.acmeKeyChain.publicKeySignRaw);
                    writeFileSync(sslPath + PRIVATE_KEY_SIGN, this.acmeKeyChain.privateKeySignRaw);

                    console.log('Signing Keys saved to File');
                }
            }

            if (this.jsonWebKey == undefined) {
                const jwk = await acme.createJsonWebKey(this.acmeKeyChain.publicKey);
                this.jsonWebKey = jwk.key;
                this.jsonWebKeyThumbPrint = jwk.print;
            }
        }
    }

    async internalLetsEncryptDaemon(fqdns, sslPath, certificateCallback, optStaging, dnsProvider) {
        let domains = [];
        let account = undefined;
        let nextNonce = undefined;
        let firstNonce = undefined;
        let authorizations = undefined;

        CF_Provider.dnsChallenges = [];
        this.challengeLists = [];
        this.httpChallenges = [];

        firstNonce = await acme.newNonce(this.acmeDirectory.newNonce);

        if (firstNonce.nonce == undefined) {
            console.error("Error getting nonce", firstNonce.error);
            return false;
        }

        account = await acme.createAccount(firstNonce.nonce, this.acmeKeyChain.privateKey, this.jsonWebKey, this.acmeDirectory).catch(console.error);

        if (account.get == undefined || account.get.status != VALID) {
            console.error("Error creating account", account.error);
            return false;
        }

        fqdns.forEach((element) => {
            domains.push({ "type": "dns", "value": element });
        });

        console.log("Creating Order", fqdns);

        const order = await acme.createOrder(account.location, account.nonce, this.acmeKeyChain.privateKey, domains, this.acmeDirectory);

        if (order.get == undefined) {
            console.error("Error getting order", order.error);
            return false;
        }

        console.log("Next Nonce", (nextNonce = order.nonce));

        authorizations = order.get.authorizations;

        for (let index = 0; index < authorizations.length; index++) {
            const auth = await acme.postAsGet(account.location, nextNonce, this.acmeKeyChain.privateKey, authorizations[index], this.acmeDirectory);

            if (auth.get) {
                this.challengeLists.push(auth);

                console.log("Next Nonce", (nextNonce = auth.nonce));
            } else {
                console.error("Error getting auth", auth.error);
            }
        }

        if (dnsProvider != undefined) {
            console.log("DNS Provider", dnsProvider.name);

            switch (dnsProvider.name) {
                case 'Cloud Flare': {
                    CF_Provider.dnsChallenges = util.extractChallengeType(this.challengeLists, DNS);

                    for (let index = 0; index < CF_Provider.dnsChallenges.length; index++) {
                        CF_Provider.dnsChallenges[index].answer = acme.base64urlEncode(createHash("sha256").update(`${CF_Provider.dnsChallenges[index].token}.${this.jsonWebKeyThumbPrint}`).digest());
                    }

                    if (await CF_Provider.internalCloudFlareProvider(dnsProvider, account, this.acmeDirectory, nextNonce, this.acmeKeyChain)) {
                        return false;
                    }

                    nextNonce = acme.getNextNonce(null, this.acmeDirectory);
                    break;
                }

                default: {
                    console.log("Unknown DNS Provider, please make sure the name is correct and the correct information was provided, currently supported: ['Cloud Flare']");
                    return false;
                }
            }
        }
        else {
            this.httpChallenges = util.extractChallengeType(this.challengeLists, HTTP);

            for (let index = 0; index < this.httpChallenges.length; index++) {
                if (this.httpChallenges[index].type == HTTP && this.httpChallenges[index].status == STATUS_PENDING) {
                    const auth = await acme.postAsGetChal(account.location, nextNonce, this.acmeKeyChain.privateKey, this.httpChallenges[index].url, this.acmeDirectory);
                    auth.get.status ? console.log("Next Nonce", (nextNonce = auth.nonce), "Authed Challenge") : console.error("Error getting auth", auth.error);
                }
            }
        }

        console.log("Completing Challenges and Preparing to Finalize");

        let finalizedCertificateLocation = null;
        let finalizedLocation = null;
        let finalizedInfo = null;

        const finalizeInfo = await new Promised().bool(async () => {
            const response = await acme.postAsGet(account.location, nextNonce, this.acmeKeyChain.privateKey, order.location, this.acmeDirectory);

            nextNonce = response.nonce;

            if (response.get && response.get.status == "ready") {
                finalizedInfo = response.get.finalize;
                return true;
            }

            return false;
        });

        if (!finalizeInfo) {
            console.log("Unable to Finalize Information", fqdns);
            return false;
        }

        console.log("Ready to Finalize Certificate", fqdns);

        const certLocation = await new Promised().bool(async () => {
            const response = await acme.finalizeOrder(fqdns[0], account.location, nextNonce, this.acmeKeyChain.privateKey, this.acmeKeyChain.publicKeySign, this.acmeKeyChain.privateKeySign, finalizedInfo, fqdns, this.acmeDirectory);

            if (response.get) {
                if (response.get.status == "processing" || response.get.status == VALID) {
                    finalizedLocation = response.location;
                    console.log("Certificate Location", finalizedLocation);
                    return true;
                }
            }
            else {
                console.error("Error getting order", response.error);
            }

            console.log("Next Nonce", (nextNonce = response.nonce));

            return false;
        });

        if (!certLocation) {
            console.log("Unable to get Certificate Location", fqdns);
            return false;
        }

        console.log("Waiting for Certificate to be Ready for Download");

        const certReady = await new Promised().bool(async () => {
            const response = await acme.postAsGet(account.location, nextNonce, this.acmeKeyChain.privateKey, finalizedLocation, this.acmeDirectory);

            if (response.get != undefined && response.get.status == VALID) {
                finalizedCertificateLocation = response.get.certificate;
                return true;
            }

            console.log("Next Nonce", (nextNonce = response.nonce));

            return false;
        });

        if (!certReady) {
            console.log("Certificate isn't ready after wait", fqdns);
            return false;
        }

        console.log("Certificate URL:", finalizedCertificateLocation);

        const response = await acme.fetchAndRetryUntilOk(finalizedCertificateLocation);

        if (response && response.ok) {
            const certificateText = await response.text();

            if (util.checkCertificateTextValid(certificateText) && util.checkPrivateKeyValid(this.acmeKeyChain.privateKeySignRaw.toString())) {
                console.log("Certificate Downloaded, Saving to file");

                writeFileSync(join(sslPath, "certificate.pem"), certificateText);

                writeFileSync(join(sslPath, "private-key.pem"), this.acmeKeyChain.privateKeySignRaw);

                writeFileSync(join(sslPath, LAST_CERT_FILE), JSON.stringify({ time: Date.now(), names: fqdns, staging: optStaging }));

                setTimeout(async () => {
                    console.log(await this.internalUpdateSuggestFromText(certificateText, this.acmeDirectory));
                    this.internalExpireDateFromCertificate(join(sslPath, "certificate.pem"));
                    this.remaining.message && console.log(this.remaining.message);
                }, 5000);

                await certificateCallback();

                !dnsProvider && await this.internalCheckAnswered();

                return true;
            }
            else {
                console.error("Something went wrong generating the certificate or the private key, will try again at the usual time");
            }
        } else {
            console.error("Something went wrong fetching the certificate, will try again at the usual time");
        }

        return false;
    }

    async internalFetchSuggest(sslPath, acmeDirectory) {
        const path = join(sslPath, "certificate.pem");

        existsSync(path) && await this.internalUpdateSuggestFromText(readFileSync(path, "utf8"), acmeDirectory);
    }

    async internalUpdateSuggestFromText(certificateText, acmeDirectory) {
        try {
            const certPem = asn1.pemToBuffer(certificateText);

            if (certPem != null) {
                const a = await asn1.decodeAKI(certPem);
                const s = await asn1.decodeSerialNumber(certPem);

                if (a == undefined || s == undefined) {
                    return undefined;
                }

                const window = await acme.fetchSuggestedWindow(acmeDirectory.renewalInfo, a, s);

                window.get != undefined && (this.ariWindow = window.get.suggestedWindow);

                return this.ariWindow;
            }
            else {
                console.error("Certificate was null, you should report this as an issue");
            }
        } catch (exception) {
            console.error(exception);
        }
    }

    internalCheckForLocalHostOnce(req) {
        if (this.checkedForLocalHost === false && this.localHost === false) {
            this.checkedForLocalHost = true;

            let ip = req.socket.remoteAddress;

            if (req.headers['x-forwarded-for']) {
                ip = req.headers['x-forwarded-for'].split(',')[0];
            }

            if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
                this.localHost = true;
                console.error(ip, req.headers.host, "You can not generate lets encrypt certificates for localhost");

                return true;
            }
        }

        return false;
    }

    internalCheckChallenges() {
        for (let index = 0; index < this.httpChallenges.length; index++) {
            if (this.httpChallenges[index].answered === false) {
                return false;
            }
        }

        if (this.httpChallenges.length > 0) {
            this.httpChallenges = [];
            console.log(REDIRECT_ONLY);
        }

        return true;
    }

    internalDetermineRequirement(fqdns, certFilePath, optStaging) {
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

            if (this.ariWindow != undefined) {
                const nowUtc = new Date().getTime();
                const startT = new Date(this.ariWindow.start).getTime();
                const endT = new Date(this.ariWindow.end).getTime();

                if (startT > nowUtc && endT > nowUtc) {
                    console.log("Automated Renewal Information Window", this.ariWindow);
                    ok = true;
                }
                else if (startT < nowUtc && endT > nowUtc) {
                    ok = false;
                    console.log("Inside Renewal Window - Generating Certificates", this.ariWindow);
                }
                else {
                    console.log("Outside Renewal Window - Generating Certificates", this.ariWindow);
                    ok = false;
                }
            }

            this.internalExpireDateFromCertificate(join(certFilePath, "certificate.pem"));
            this.remaining.days && console.log(this.remaining.message);
        }

        return ok;
    }

    internalExpireDateFromCertificate(__certPath) {
        const output = runCommandSync(`x509 -in "${__certPath}" -enddate -noout`);

        if (output != undefined) {
            try {
                const specificDate = new Date(output);
                const currentDate = new Date();

                const t = specificDate.getTime() - currentDate.getTime();

                if (t > 0) {
                    const d = Math.floor(t / (1000 * 60 * 60 * 24));

                    if (d > 0) {
                        this.remaining.days = d;
                        this.remaining.hours = Math.floor((t % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                        this.remaining.minutes = Math.floor((t % (1000 * 60 * 60)) / (1000 * 60));
                        this.remaining.message = `Time until renewal required: ${this.remaining.days} days, ${this.remaining.hours} hours, ${this.remaining.minutes} minutes`;
                        return;
                    }
                }
            } catch (exception) {
                console.log(exception); // Not a date
            }
        }

        this.remaining = { days: null, hours: null, minutes: null };
    }
}