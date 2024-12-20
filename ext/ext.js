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

/**
 * Checks if the given certificate text is valid.
 * A valid certificate text starts with "-----BEGIN CERTIFICATE-----"
 * and ends with "-----END CERTIFICATE-----" (with or without a newline).
 *
 * @param {string} certificateText - The certificate text to validate.
 * @returns {boolean} True if the certificate text is valid, false otherwise.
 */
export function checkCertificateTextValid(certificateText) {
    return certificateText.startsWith("-----BEGIN CERTIFICATE-----") && (certificateText.endsWith("-----END CERTIFICATE-----\n") || certificateText.endsWith("-----END CERTIFICATE-----") || certificateText.endsWith("-----END CERTIFICATE----- "));
}

/**
 * Checks if the given private key is valid.
 * A valid private key starts with "-----BEGIN PRIVATE KEY-----"
 * and ends with "-----END PRIVATE KEY-----" (with or without a newline).
 *
 * @param {string} privateKey - The private key to validate.
 * @returns {boolean} True if the private key is valid, false otherwise.
 */
export function checkPrivateKeyValid(privateKey) {
    return privateKey.startsWith("-----BEGIN PRIVATE KEY-----") && (privateKey.endsWith("-----END PRIVATE KEY-----") || privateKey.endsWith("-----END PRIVATE KEY-----\n") || privateKey.endsWith("-----END PRIVATE KEY----- "))
}

/**
 * Extracts challenges of a specific type from a list of authorizations.
 * Each challenge is marked as unanswered and includes its associated domain
 * and wildcard status.
 *
 * @param {Array} list - The list of authorizations containing challenges.
 * @param {string} challengeType - The type of challenge to extract.
 * @returns {Array} An array of challenges of the specified type.
 */
export function extractChallengeType(list, challengeType) {
    const chals = [];

    for (let index = 0; index < list.length; index++) {
        const auth = list[index];

        for (let i1 = 0; i1 < auth.get.challenges.length; i1++) {
            const challenge = auth.get.challenges[i1];
            challenge.type == challengeType && (challenge.answered = false, challenge.domain = auth.get.identifier.value, challenge.wildcard = auth.get.wildcard ? auth.get.wildcard : false, chals.push(challenge));
        }
    }

    return chals;
}