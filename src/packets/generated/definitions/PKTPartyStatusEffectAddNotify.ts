// Auto Generated, do not edit.
import { Read } from "../../stream";
import * as StatusEffectData from "../structures/StatusEffectData";
export type PKTPartyStatusEffectAddNotify = {
  unk0: bigint;
  characterId: bigint;
  playerIdOnRefresh: bigint;
  statusEffectDatas: StatusEffectData.StatusEffectData[];
  unk4: number;
};
export function read(buf: Buffer) {
  const reader = new Read(buf);
  const data = {} as PKTPartyStatusEffectAddNotify;
  data.unk0 = reader.u64();
  data.characterId = reader.u64();
  data.playerIdOnRefresh = reader.u64();
  data.statusEffectDatas = reader.array(reader.u16(), () => StatusEffectData.read(reader), 80);
  data.unk4 = reader.u8();
  return data;
}
export const name = "PKTPartyStatusEffectAddNotify";
export const opcode = 35921;
