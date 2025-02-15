// Auto Generated, do not edit.
import type { Read } from "../../stream";
import * as ReadNBytesInt64 from "../../common/ReadNBytesInt64";
import * as Vector3F from "../../common/Vector3F";
export type PartyMemberData = {
  name: string;
  worldId: number;
  auths: number;
  position: Vector3F.Vector3F;
  zoneInstId: bigint;
  classId: number;
  unk6: number;
  transitIndex: number;
  unk8: number;
  unk9: number;
  unk10: number;
  unk11: number;
  maxHp: bigint;
  partyMemberNumber: number;
  gearLevel: number;
  unk15: number;
  curHp: bigint;
  characterId: bigint;
  zoneId: number;
  characterLevel: number;
};
export function read(reader: Read) {
  const data = {} as PartyMemberData;
  data.name = reader.string(20);
  data.worldId = reader.u8();
  data.auths = reader.u8();
  data.position = Vector3F.read(reader);
  data.zoneInstId = reader.u64();
  data.classId = reader.u16();
  data.unk6 = reader.u8();
  data.transitIndex = reader.u32();
  data.unk8 = reader.u16();
  data.unk9 = reader.u8();
  data.unk10 = reader.u8();
  data.unk11 = reader.u8();
  data.maxHp = ReadNBytesInt64.read(reader);
  data.partyMemberNumber = reader.u8();
  data.gearLevel = reader.f32();
  data.unk15 = reader.u8();
  data.curHp = ReadNBytesInt64.read(reader);
  data.characterId = reader.u64();
  data.zoneId = reader.u32();
  data.characterLevel = reader.u16();
  return data;
}
