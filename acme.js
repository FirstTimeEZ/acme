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

import { createPrivateKey, createPublicKey, createHash, sign } from 'crypto';
import { generateCSRWithExistingKeys } from 'simple-csr-generator';

const CONTENT_TYPE = "Content-Type";

const DIGEST = "sha256";
const ALG_ECDSA = 'ES256';

const CONTENT_TYPE_JOSE = 'application/jose+json';

const METHOD_GET = "GET";
const METHOD_POST = "POST";
const METHOD_HEAD = "HEAD";
const METHOD_POST_AS_GET = "";
const METHOD_POST_AS_GET_CHALLENGE = {};

const SAN = "identifiers";
const NEXT_URL = "location";
const REPLAY_NONCE = 'replay-nonce';

export async function newDirectoryAsync(mainDirectoryUrl) {
    return new Promise((resolve) => {
        fetch(mainDirectoryUrl, { method: METHOD_GET }).then(response => {
            response.ok
                ? response.json().then((result) => { resolve({ answer: { directory: result } }); }).catch((exception) => resolve({ answer: { exception: exception } }))
                : resolve({ answer: { error: response } });
        }).catch((exception) => resolve({ answer: { exception: exception } }));
    });
}

export async function newNonceAsync(newNonceUrl) {
    let nonceUrl = newNonceUrl;

    if (newNonceUrl == undefined) {
        const directory = (await newDirectoryAsync()).answer.directory;
        if (directory !== null) {
            nonceUrl = directory.newNonce;
        }
    }

    if (nonceUrl !== null) {
        return new Promise(async (resolve) => {
            fetch(nonceUrl, {
                method: METHOD_HEAD
            }).then((response) => response.ok
                ? resolve({ answer: { response: response }, nonce: response.headers.get(REPLAY_NONCE) })
                : resolve({ answer: { error: response } }))
                .catch((exception) => resolve({ answer: { exception: exception } }));;
        });
    } else {
        return { answer: { error: "No directories found or newNonce is not available." } };
    }
}

export async function createJsonWebKey(publicKey) {
    const jsonWebKey = publicKey.export({ format: 'jwk' });

    return { key: jsonWebKey, print: base64urlEncode(createHash(DIGEST).update(new TextEncoder().encode(JSON.stringify({ crv: jsonWebKey.crv, kty: jsonWebKey.kty, x: jsonWebKey.x, y: jsonWebKey.y }))).digest()) };
}

export async function createAccount(nonce, newAccountUrl, privateKey, jsonWebKey) {
    try {
        const payload = { termsOfServiceAgreed: true };

        const protectedHeader = {
            alg: ALG_ECDSA,
            jwk: jsonWebKey,
            nonce: nonce,
            url: newAccountUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, newAccountUrl, signed);

        if (response.ok) {
            return {
                answer: { account: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

export async function createOrder(kid, nonce, privateKey, newOrderUrl, identifiers) {
    try {
        const payload = { [SAN]: identifiers };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: newOrderUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, newOrderUrl, signed);

        if (response.ok) {
            return {
                answer: { order: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

export async function finalizeOrder(commonName, kid, nonce, privateKey, publicKeySign, privateKeySign, finalizeUrl, dnsNames) {
    try {
        const payload = { csr: await generateCSRWithExistingKeys(commonName, publicKeySign, privateKeySign, dnsNames) };

        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: finalizeUrl,
        };

        const signed = await signPayloadJson(payload, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, finalizeUrl, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

export async function postAsGet(kid, nonce, privateKey, url) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const signed = await signPayload(METHOD_POST_AS_GET, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, url, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

export async function postAsGetChal(kid, nonce, privateKey, url) {
    try {
        const protectedHeader = {
            alg: ALG_ECDSA,
            kid: kid,
            nonce: nonce,
            url: url,
        };

        const signed = await signPayloadJson(METHOD_POST_AS_GET_CHALLENGE, protectedHeader, privateKey);

        const response = await fetchRequest(METHOD_POST, url, signed);

        if (response.ok) {
            return {
                answer: { get: await response.json(), location: response.headers.get(NEXT_URL) },
                nonce: response.headers.get(REPLAY_NONCE)
            };
        }
        else {
            return {
                answer: { error: await response.json() },
                nonce: null
            };
        }
    } catch (exception) {
        return { answer: { exception: exception } }
    }
}

export async function signPayloadJson(payload, protectedHeader, privateKey) {
    return await signPayload(JSON.stringify(payload), protectedHeader, privateKey);
}

export async function signPayload(payload, protectedHeader, privateKey) {
    const payload64 = base64urlEncode(new TextEncoder().encode(payload));
    const protected64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(protectedHeader)));

    const jws = {
        signature: base64urlEncode(sign("sha256", `${protected64}${'.'}${payload64}`, { dsaEncoding: 'ieee-p1363', key: privateKey })),
        payload: "",
        protected: protected64
    };

    if (payload.length > 1) {
        jws.payload = payload64
    }

    return JSON.stringify(jws);
}

export async function fetchRequest(method, url, signedData) {
    const request = {
        method: method,
        headers: {
            [CONTENT_TYPE]: CONTENT_TYPE_JOSE
        },
        body: signedData
    };

    return await fetch(url, request);
}

export function formatPublicKey(pem) {
    return createPublicKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, ''), 'base64'), type: 'spki', format: 'der' });
}

export function formatPrivateKey(pem) {
    return createPrivateKey({ key: Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, ''), 'base64'), type: 'pkcs8', format: 'der' });
}

export function base64urlEncode(input) {
    const base64 = Buffer.from(typeof input === 'string' ? new TextEncoder().encode(input) : input).toString('base64');

    return base64
        .replace(/\+/g, '-')   // Replace + with -
        .replace(/\//g, '_')   // Replace / with _
        .replace(/=+$/, '');   // Remove trailing =
}