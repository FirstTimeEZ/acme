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
 * A utility class for handling Promise-based checks with retry mechanism
 */
export default class Promised {
    /**
     * Repeatedly checks a boolean condition with an exponential backoff strategy
     * @async
     * 
     * @param {Function} boolFunc - An async function that returns a boolean
     * @param {number} [max=5] - Maximum number of attempts to check the condition
     * @returns {Promise<boolean>} 
     * - Returns true if the condition becomes true within the max attempts
     * - Returns false if the condition remains false after max attempts
     * 
     * @description
     * This method implements a retry mechanism with the following characteristics:
     * - Checks the condition every 1.5 seconds
     * - Increases wait time between attempts exponentially
     * - Stops and returns true as soon as the condition becomes true
     * - Stops and returns false if max attempts are reached
     * 
     */
    async bool(boolFunc, max = 5) {
        return await new Promise((resolve) => {
            let n = 0;

            const checkCondition = async () => {
                if (await boolFunc()) {
                    resolve(true);
                    return;
                }

                if (n >= max) {
                    resolve(false);
                    return;
                }

                n++;

                setTimeout(() => { checkCondition(); }, Math.pow(2, n) * 650);
            };

            checkCondition();
        });
    }
}
