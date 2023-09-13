// Auto Generated, do not edit.
import { Read } from "../../stream";
export type PKTTriggerFinishNotify = {
  triggerId: number;
  involvedPCs: bigint[];
  packetResultCode: number;
  unk0_m: number;
};
export function read(buf: Buffer) {
  const reader = new Read(buf);
  const data = {} as PKTTriggerFinishNotify;
  data.triggerId = reader.u32();
  data.involvedPCs = reader.array(reader.u16(), () => reader.u64(), 40);
  data.packetResultCode = reader.u32();
  data.unk0_m = reader.u32();
  return data;
}
export const name = "PKTTriggerFinishNotify";
export const opcode = 8729;
