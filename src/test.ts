import { createReadStream, createWriteStream, readFileSync } from "fs";
import { MeterData } from "./data";
import { Decompressor } from "./decompressor";
import { LiveLogger, Logger, ReplayLogger } from "./logger/logger";
import { PktCaptureAll, PktCaptureMode } from "./pkt-capture";
import { PKT, PKTStream } from "./pkt-stream";
import { Parser } from "./logger/parser";
import { mapping } from "./packets/generated/mapping";
import { LogEvent } from "./logger/logEvent";
import { damagetype, hitflag, itemstoragetype, stattype, triggersignaltype } from "./packets/generated/enums";
import * as reads from "./packets/generated/reads";
import { logId } from "./packets/log/logIds";
import { logMapping } from "./packets/log/logMapping";
import * as Vector3F from "./packets/common/Vector3F";
import { Read } from "./packets/stream";

import { inspect } from "util";
inspect.defaultOptions.depth = null; //Use to console log full objects for debug

const oodle_state = readFileSync("./meter-data/oodle_state.bin");
const xorTable = readFileSync("./meter-data/xor.bin");
const compressor = new Decompressor(oodle_state, xorTable);

// create Decompressor & LegacyLogger
const stream = new PKTStream(compressor);

const logger = new LiveLogger(stream, compressor);
const meterData = new MeterData(require.resolve("meter-core/data"));
meterData.loadDbs("./meter-data/databases");

// finaly create packet capture
const capture = new PktCaptureAll(
    true ? PktCaptureMode.MODE_RAW_SOCKET : PktCaptureMode.MODE_PCAP,
    6040
);
console.log(
    `Listening on ${capture.captures.size} devices(s): ${Array.from(
        capture.captures.keys()
    ).join(", ")}`
);
capture.on("packet", (buf) => {
    try {
        const badPkt = stream.read(buf);
        if(badPkt === false) console.error(`bad pkt ${buf.toString("hex")}`);
    } catch(e) {
        console.error(e);
    }
});





stream.on("*", (data, opcode, compression, xor) => {

    let map = mapping.get(opcode);
    if(!map) {
        let buf = compressor.decrypt(data, opcode, compression, xor)
        console.log("Unknown pkt", opcode, "data:", buf)
        return
    }
    const [name, read] = map;
    let pkt = new PKT(Buffer.from(data), opcode, compression, Boolean(xor), compressor, read)
    console.log(name, pkt.parsed)
})

