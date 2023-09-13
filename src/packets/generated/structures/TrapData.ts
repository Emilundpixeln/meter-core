// Auto Generated, do not edit.
import type { Read } from "../../stream";
import * as Vector3F from "../../common/Vector3F";
export type TrapData = {
  unk0: number;
  struct_327?: Buffer;
  skillId: number;
  unk4: number;
  unk5: number;
  position: Vector3F.Vector3F;
  ownerId: bigint;
  unk8: number;
  objectId: bigint;
  unk10: number;
  unk11: number;
  skillEffect: number;
  unk13: number;
};
export function read(reader: Read) {
  const data = {} as TrapData;
  data.unk0 = reader.u32();
  if (reader.bool()) data.struct_327 = reader.bytes(reader.u16(), 11, 9);
  data.skillId = reader.u32();
  data.unk4 = reader.u8();
  data.unk5 = reader.u32();
  data.position = Vector3F.read(reader);
  data.ownerId = reader.u64();
  data.unk8 = reader.u32();
  data.objectId = reader.u64();
  data.unk10 = reader.u16();
  data.unk11 = reader.u8();
  data.skillEffect = reader.u32();
  data.unk13 = reader.u8();
  return data;
}
