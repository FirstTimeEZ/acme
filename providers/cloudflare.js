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

import * as acme from 'base-acme-client';

const STATUS_PENDING = "pending";

/**
 * Cloudflare Provider
 */
export const CF_Provider = {
    dnsChallenges: [],
    internalCloudFlareProvider: async (dnsProvider, account, acmeDirectory, nextNonce, acmeKeyChain) => {
        if (dnsProvider.token == undefined) {
            console.log("Expected API Token with DNS Edit permissions for Cloudflare DNS Provider");
            return true;
        }
        
        for (let index = 0; index < CF_Provider.dnsChallenges.length; index++) {
            if (CF_Provider.dnsChallenges[index].status == STATUS_PENDING) {
                const response = await findOrCreateRecord(dnsProvider.token, CF_Provider.dnsChallenges[index].domain, CF_Provider.dnsChallenges[index].answer, dnsProvider.zone);
                console.log(response);
            }
        }

        const wait = CF_Provider.dnsChallenges.some(e => e.status == STATUS_PENDING);

        if (wait) {
            await new Promise((resolve) => {
                console.log("Waiting a minute before asking server to verify the challenges");
                setTimeout(async () => {
                    for (let index = 0; index < CF_Provider.dnsChallenges.length; index++) {
                        if (CF_Provider.dnsChallenges[index].status == STATUS_PENDING) {
                            const auth = await acme.postAsGetChal(account.location, nextNonce, acmeKeyChain.privateKey, CF_Provider.dnsChallenges[index].url, acmeDirectory);
                            auth.get.status ? console.log("Next Nonce", (nextNonce = auth.nonce), "Authed Challenge") : console.error("Error getting auth", auth.error);
                        }
                    }

                    resolve();
                }, 60000);
            });
        } else {
            console.log("Already Completed Challenges");
        }

        return false;
    }
}

export function extractZoneName(split) {
    let name = "";

    for (let index = 1; index < split.length; index++) {
        name += `${split[index]}`
        if (index + 1 < split.length) {
            name += ".";
        }
    }

    return name;
}

async function getZone(apiToken, domainName) {
    const response = await acme.fetchAndRetryUntilOk(`https://api.cloudflare.com/client/v4/zones`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiToken}`,
            'Content-Type': 'application/json'
        }
    }, 2);

    if (response && response.ok) {
        const zones = await response.json();

        for (let index = 0; index < zones.result.length; index++) {
            if (zones.result[index].name.includes(domainName)) {
                return zones.result[index].id;
            }

            if (zones.result[index].name.includes(extractZoneName(domainName.split('.')))) {
                return zones.result[index].id;
            }
        }
    }

    return undefined;
}

async function getRecords(zoneId, apiToken) {
    const response = await acme.fetchAndRetryUntilOk(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiToken}`,
            'Content-Type': 'application/json'
        }
    }, 2);

    if (response && response.ok) {
        return await response.json();
    }
    else {
        return undefined;
    }
}

function findChallengeRecord(data, token) {
    for (let index = 0; index < data.result.length; index++) {
        const element = data.result[index];

        if (element.type == "TXT" && element.content.includes(token)) {
            return element;
        }
    }

    return undefined;
}

async function findOrCreateRecord(apiToken, domainName, token, zone = undefined) {
    if (zone == undefined) {
        zone = await getZone(apiToken, domainName);
    }

    if (zone == undefined) {
        return errorTemplate("cf:failed:zone", "Could not dertermine the DNS zone of the Domain Name Provided", 877771);
    }

    const zoneDnsRecords = await getRecords(zone, apiToken);

    if (zoneDnsRecords == undefined) {
        return errorTemplate("cf:failed:zoneDnsRecords", "Could not get DNS Records, check your zoneId and apiToken", 877772);
    }

    let challengeRecord = findChallengeRecord(zoneDnsRecords, token);

    challengeRecord && console.log("Found", challengeRecord.content);

    if (challengeRecord == undefined) {

        const newRecord = await createRecord(domainName, token, zone, apiToken, 60);
        if (newRecord) {
            challengeRecord = newRecord.result;
            challengeRecord.changed = true;

            challengeRecord && console.log("Created", challengeRecord.content);
        }

    }

    return {
        get: challengeRecord
    }
}

async function createRecord(domainName, challengeToken, dnsZoneId, cloudFlareApiToken, ttl = 3600) {

    domainName.includes("*.") && (domainName = domainName.slice(2));

    const dnsRecord = {
        comment: "Domain verification record",
        name: "_acme-challenge." + domainName,
        content: `"${challengeToken}"`,
        ttl: ttl,
        type: "TXT"
    };

    const response = await acme.fetchAndRetryUntilOk(`https://api.cloudflare.com/client/v4/zones/${dnsZoneId}/dns_records`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${cloudFlareApiToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(dnsRecord)
    }, 2);

    if (response && response.ok) {
        return await response.json();
    }
    else {
        return undefined;
    }
}

async function updateRecord(challengeToken, dnsZoneId, cloudFlareApiToken, dnsRecordId) {
    const dnsRecord = {
        content: `"${challengeToken}"`,
    };

    const response = await acme.fetchAndRetryUntilOk(`https://api.cloudflare.com/client/v4/zones/${dnsZoneId}/dns_records/${dnsRecordId}`, {
        method: 'PATCH',
        headers: {
            'Authorization': `Bearer ${cloudFlareApiToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(dnsRecord)
    });

    if (response && response.ok) {
        return await response.json();
    }
    else {
        return undefined;
    }
}

function errorTemplate(type, details, status) {
    return {
        error: {
            type: type,
            detail: details,
            status: status
        }
    }
}