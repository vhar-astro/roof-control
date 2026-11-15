// One-time cloud call: fetch local_key and DP ID mapping for the roof device.
// After this, all control can be done fully locally (TCP 6668).
require('dotenv').config();
const { TuyaContext } = require('@tuya/tuya-connector-nodejs');

const deviceId = process.env.TUYA_DEVICE_ID;

const tuya = new TuyaContext({
    accessKey: process.env.TUYA_ACCESS_ID,
    secretKey: process.env.TUYA_ACCESS_KEY,
    baseUrl: process.env.TUYA_API_ENDPOINT,
});

(async () => {
    // 1) Device details -> local_key, product info, protocol version hints
    for (const path of [
        `/v1.0/iot-03/devices/${deviceId}`,
        `/v1.0/devices/${deviceId}`,
        `/v2.0/cloud/thing/${deviceId}/device`,
    ]) {
        try {
            const res = await tuya.request({ method: 'GET', path });
            console.log(`\n=== GET ${path} ===`);
            console.log('FULL RESPONSE:', JSON.stringify(res, null, 2));
            if (res && res.success && res.result && (res.result.local_key || res.result.uuid)) break;
        } catch (e) {
            console.log(`\n=== GET ${path} FAILED: ${e.message} ===`);
            if (e.response) console.log('BODY:', JSON.stringify(e.response.body ?? e.response.data ?? e.response, null, 2));
        }
    }

    // 2) Thing model -> numeric DP ids for codes (wfh_open, l_open, ...)
    for (const path of [
        `/v2.0/cloud/thing/${deviceId}/model`,
        `/v2.0/cloud/thing/${deviceId}/shadow/properties`,
    ]) {
        try {
            const res = await tuya.request({ method: 'GET', path });
            console.log(`\n=== GET ${path} ===`);
            console.log('FULL RESPONSE:', JSON.stringify(res, null, 2));
        } catch (e) {
            console.log(`\n=== GET ${path} FAILED: ${e.message} ===`);
            if (e.response) console.log('BODY:', JSON.stringify(e.response.body ?? e.response.data ?? e.response, null, 2));
        }
    }
})();
