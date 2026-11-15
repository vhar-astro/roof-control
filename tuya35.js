// tuya35.js — Tuya Protocol 3.5 local client (AES-128-GCM, 0x00006699 framing)
// Pure Node, zero cloud calls at runtime. Implemented per tinytuya's reference
// logic (github.com/jasonacox/tinytuya).
//
// Wire format:
//   frame = [00 00 66 99][unknown u16][seq u32][cmd u32][len u32][iv 12][ciphertext][tag 16][00 00 99 66]
//   len field = ciphertext length + 28 (counts iv+tag, not the 4-byte suffix)
//   AAD = frame bytes 4..18. Key = localKey during handshake, sessionKey after.
//   Received plaintext = [retcode u32][optional "3.5"+12*0 version header][JSON]
//
// Session key negotiation:
//   1. send cmd 3 (SESS_KEY_NEG_START): 16-byte random nonce (GCM with localKey)
//   2. recv  cmd 4 (SESS_KEY_NEG_RESP): retcode + remote nonce(16) + HMAC-SHA256(localKey, our nonce)(32)
//   3. send cmd 5 (SESS_KEY_NEG_FINISH): HMAC-SHA256(localKey, remote nonce)
//   4. sessionKey = AES-GCM(localKey, iv=localNonce[0:12]).encrypt(XOR(nonces)).ciphertext
//
// Commands after handshake (encrypted with sessionKey):
//   DP_QUERY_NEW (16): payload "{}" (no version header — query cmds are exempt)
//   CONTROL_NEW  (13): payload "3.5" + 12*0x00 + {"protocol":5,"t":<unix>,"data":{"dps":{...}}}
//
// CLI usage:
//   node tuya35.js status [--json]
//   node tuya35.js open|close|stop --yes        (roof motion; requires --yes)
//   node tuya35.js set <dpId> <value> --yes
//   node tuya35.js watch [--interval 2000]      (live status monitor, Ctrl+C to stop)
// Config: .env.local (TUYA_LOCAL_IP, TUYA_DEVICE_ID, TUYA_LOCAL_KEY)

'use strict';
const net = require('net');
const crypto = require('crypto');

const PREFIX_6699 = 0x00006699;
const SUFFIX_6699 = Buffer.from([0x00, 0x00, 0x99, 0x66]);

const CMD = {
  SESS_KEY_NEG_START: 3,
  SESS_KEY_NEG_RESP: 4,
  SESS_KEY_NEG_FINISH: 5,
  CONTROL_NEW: 13,
  HEARTBEAT: 9,
  DP_QUERY_NEW: 16,
};

class Tuya35 {
  constructor({ ip, deviceId, localKey, port = 6668, timeout = 5000 }) {
    this.ip = ip;
    this.port = port;
    this.deviceId = deviceId;
    this.key = Buffer.from(localKey, 'latin1');
    if (this.key.length !== 16) throw new Error('localKey must be 16 bytes');
    this.timeout = timeout;
    this.seq = 0;
    this.sessionKey = null;
    this.socket = null;
  }

  // ---- framing ----
  buildFrame(cmd, payload, key) {
    const iv = crypto.randomBytes(12);
    const header = Buffer.alloc(18);
    header.writeUInt32BE(PREFIX_6699, 0);
    header.writeUInt16BE(0, 4);
    header.writeUInt32BE(++this.seq, 6);
    header.writeUInt32BE(cmd, 10);
    header.writeUInt32BE(payload.length + 28, 14);
    const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
    cipher.setAAD(header.subarray(4));
    const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([header, iv, ct, tag, SUFFIX_6699]);
  }

  readFrame(buf) {
    if (buf.length < 18) return null;
    const prefix = buf.readUInt32BE(0);
    if (prefix !== PREFIX_6699) throw new Error(`bad prefix 0x${prefix.toString(16)}`);
    const unknown = buf.readUInt16BE(4);
    const seq = buf.readUInt32BE(6);
    const cmd = buf.readUInt32BE(10);
    const len = buf.readUInt32BE(14);
    const total = 18 + len + 4;
    if (buf.length < total) return null; // incomplete, keep accumulating
    const frame = buf.subarray(0, total);
    if (!frame.subarray(total - 4).equals(SUFFIX_6699)) throw new Error('bad suffix');
    const iv = frame.subarray(18, 30);
    const tag = frame.subarray(18 + len - 16, 18 + len);
    const ct = frame.subarray(30, 18 + len - 16);
    return { unknown, seq, cmd, iv, tag, ct, header: frame.subarray(0, 18) };
  }

  decryptFrame(f, key) {
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, f.iv);
    decipher.setAuthTag(f.tag);
    decipher.setAAD(f.header.subarray(4));
    return Buffer.concat([decipher.update(f.ct), decipher.final()]);
  }

  // ---- socket helpers ----
  connect() {
    return new Promise((resolve, reject) => {
      const s = new net.Socket();
      s.setTimeout(this.timeout);
      const onErr = (e) => { cleanup(); reject(e); };
      const cleanup = () => { s.off('error', onErr); };
      s.once('error', onErr);
      s.connect(this.port, this.ip, () => { cleanup(); s.setTimeout(0); this.socket = s; resolve(s); });
    });
  }

  // read until one complete frame arrives
  recvFrame(key, deadlineMs = 4000) {
    return new Promise((resolve, reject) => {
      const s = this.socket;
      let acc = Buffer.alloc(0);
      const timer = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for frame')); }, deadlineMs);
      const onData = (chunk) => {
        acc = Buffer.concat([acc, chunk]);
        try {
          const f = this.readFrame(acc);
          if (f) { cleanup(); resolve(f); }
        } catch (e) { cleanup(); reject(e); }
      };
      const onErr = (e) => { cleanup(); reject(e); };
      const cleanup = () => {
        clearTimeout(timer);
        s.off('data', onData);
        s.off('error', onErr);
      };
      s.on('data', onData);
      s.once('error', onErr);
    });
  }

  async sendRaw(cmd, payload, key) {
    return new Promise((resolve, reject) => {
      this.socket.write(this.buildFrame(cmd, payload, key), (e) => (e ? reject(e) : resolve()));
    });
  }

  // ---- session handshake ----
  async handshake() {
    const localNonce = crypto.randomBytes(16);
    await this.sendRaw(CMD.SESS_KEY_NEG_START, localNonce, this.key);
    const f = await this.recvFrame(this.key);
    if (f.cmd !== CMD.SESS_KEY_NEG_RESP) throw new Error(`expected SESS_KEY_NEG_RESP (4), got cmd ${f.cmd}`);
    const pt = this.decryptFrame(f, this.key);
    // plaintext = retcode(4) + remoteNonce(16) + hmac(32)
    const retcode = pt.readUInt32BE(0);
    if (retcode !== 0) throw new Error(`handshake rejected, retcode ${retcode}`);
    const remoteNonce = pt.subarray(4, 20);
    const remoteHmac = pt.subarray(20, 52);
    const expectHmac = crypto.createHmac('sha256', this.key).update(localNonce).digest();
    if (!remoteHmac.equals(expectHmac)) throw new Error('HMAC mismatch — wrong local key');
    // send FINISH: HMAC(realKey, remoteNonce); no reply expected
    const finishHmac = crypto.createHmac('sha256', this.key).update(remoteNonce).digest();
    await this.sendRaw(CMD.SESS_KEY_NEG_FINISH, finishHmac, this.key);
    // sessionKey = GCM(realKey, iv=localNonce[:12]).encrypt(XOR(nonces)).ciphertext
    const xored = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) xored[i] = localNonce[i] ^ remoteNonce[i];
    const cipher = crypto.createCipheriv('aes-128-gcm', this.key, localNonce.subarray(0, 12));
    this.sessionKey = Buffer.concat([cipher.update(xored), cipher.final()]); // 16-byte ciphertext
    return true;
  }

  // ---- high level ----
  async open() {
    await this.connect();
    await this.handshake();
    return this;
  }

  close() {
    if (this.socket) { try { this.socket.destroy(); } catch {} this.socket = null; }
    this.sessionKey = null;
  }

  static decodePayload(pt) {
    let data = pt.subarray(4); // strip retcode
    // strip optional "3.5"/"3.4" version header (3 bytes + 12 zero bytes)
    const head = data.subarray(0, 15).toString('latin1');
    if ((head.startsWith('3.5') || head.startsWith('3.4')) &&
        data.subarray(3, 15).every((b) => b === 0)) {
      data = data.subarray(15);
    }
    const text = data.toString('utf8');
    try { return JSON.parse(text); } catch { return text; }
  }

  async status() {
    await this.sendRaw(CMD.DP_QUERY_NEW, Buffer.from('{}'), this.sessionKey);
    const f = await this.recvFrame(this.sessionKey);
    const pt = this.decryptFrame(f, this.sessionKey);
    const decoded = Tuya35.decodePayload(pt);
    // {"dps":{...}} or {"data":{"dps":{...}},...}
    if (decoded && typeof decoded === 'object' && decoded.data && decoded.data.dps && !decoded.dps) {
      decoded.dps = decoded.data.dps;
    }
    return decoded;
  }

  async setDps(dps) {
    // CONTROL_NEW is not in NO_PROTOCOL_HEADER_CMDS -> prepend "3.5" + 12 zero bytes version header
    const json = Buffer.from(JSON.stringify({
      protocol: 5,
      t: Math.floor(Date.now() / 1000),
      data: { dps },
    }).replace(/ /g, ''));
    const payload = Buffer.concat([Buffer.from('3.5', 'latin1'), Buffer.alloc(12), json]);
    await this.sendRaw(CMD.CONTROL_NEW, payload, this.sessionKey);
    // device may ACK with empty payload or a status update; read best-effort
    try {
      const f = await this.recvFrame(this.sessionKey, 2500);
      const pt = this.decryptFrame(f, this.sessionKey);
      return Tuya35.decodePayload(pt);
    } catch {
      return null; // no ACK — assume accepted
    }
  }
}

module.exports = Tuya35;

// ---- CLI ----
if (require.main === module) {
  require('dotenv').config({ path: __dirname + '/.env.local', quiet: true });
  const IP = process.env.TUYA_LOCAL_IP || '192.168.1.151';
  const ID = process.env.TUYA_DEVICE_ID;
  const KEY = process.env.TUYA_LOCAL_KEY;

  // TY-WFH V3.01 DP map (community-verified, matches this device's cloud DP codes)
  const DP = {
    open: 101, close: 102, stop: 103, lock: 104,
    return_state: 105, l_close: 106, l_open: 107,
    inrf: 108, fsw: 109, fast_op: 110, hidden_state: 111, wfh_rssi: 112,
  };
  const NAME = Object.fromEntries(Object.entries(DP).map(([k, v]) => [v, k]));
  const RETURN_STATE = { 2: 'opening', 3: 'open', 4: 'closing', 5: 'closed', 6: 'locked', 11: 'stopped', 12: 'open', 13: 'closed' };

  function summarize(dps) {
    const l_open = dps[String(DP.l_open)] === true;
    const l_close = dps[String(DP.l_close)] === true;
    const rs = dps[String(DP.return_state)];
    let roof;
    if (l_open) roof = 'OPEN';
    else if (l_close) roof = 'CLOSED';
    else roof = `MOVING/UNKNOWN (${RETURN_STATE[rs] || 'state ' + rs})`;
    return { roof, return_state: rs, return_state_text: RETURN_STATE[rs] || '?', dps };
  }

  const cmd = process.argv[2] || 'status';
  const args = process.argv.slice(3);

  async function connect() {
    return new Tuya35({ ip: IP, deviceId: ID, localKey: KEY }).open();
  }

  (async () => {
    if (cmd === 'status') {
      const dev = await connect();
      try {
        const st = await dev.status();
        if (!st || !st.dps) { console.log('raw response:', JSON.stringify(st)); return; }
        const sum = summarize(st.dps);
        if (args.includes('--json')) { console.log(JSON.stringify(sum, null, 2)); return; }
        for (const k of Object.keys(st.dps).sort((a, b) => a - b)) {
          const ki = parseInt(k, 10);
          let v = st.dps[k];
          if (ki === 105) v = `${v} = ${RETURN_STATE[v] || '?'}`;
          console.log(`  ${ki}\t${NAME[ki] || '?'}\t= ${v}`);
        }
        console.log(`ROOF: ${sum.roof}`);
      } finally { dev.close(); }
    } else if (cmd === 'watch') {
      const intervalIdx = args.indexOf('--interval');
      const interval = intervalIdx >= 0 ? parseInt(args[intervalIdx + 1], 10) : 2000;
      let dev = await connect();
      let last = '';
      console.error(`watching ${IP} (poll ${interval}ms, Ctrl+C to stop)`);
      const poll = async () => {
        try {
          const st = await dev.status();
          if (!st || !st.dps) throw new Error('bad status');
          const sum = summarize(st.dps);
          const line = `ROOF: ${sum.roof}`;
          const full = JSON.stringify(sum.dps);
          if (full !== last) {
            last = full;
            console.log(`${new Date().toLocaleTimeString()}  ${line}  dps=${full}`);
          }
        } catch (e) {
          console.error(`${new Date().toLocaleTimeString()}  (${e.message} — reconnecting)`);
          try { dev.close(); } catch {}
          dev = await connect();
          last = '';
        }
        setTimeout(poll, interval);
      };
      poll();
    } else if (['open', 'close', 'stop', 'set'].includes(cmd)) {
      if (!args.includes('--yes')) {
        console.log('This may physically MOVE the roll-off roof. Re-run with --yes to confirm.');
        process.exitCode = 1;
        return;
      }
      let dp, value;
      if (cmd === 'set') {
        dp = parseInt(args[0], 10);
        value = JSON.parse(args[1]);
        if (!dp) { console.error('usage: set <dpId> <value> --yes'); process.exit(1); }
      } else {
        dp = DP[cmd];
        value = true;
      }
      const dev = await connect();
      try {
        const r = await dev.setDps({ [String(dp)]: value });
        console.log(`sent DP ${dp} (${NAME[dp] || '?'}) = ${value}`, r ? `ack: ${JSON.stringify(r)}` : '(no ack)');
      } finally { dev.close(); }
    } else {
      console.log('usage: node tuya35.js status [--json] | watch [--interval 2000] | open|close|stop --yes | set <dp> <val> --yes');
      process.exit(cmd === 'help' ? 0 : 1);
    }
  })().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
}
