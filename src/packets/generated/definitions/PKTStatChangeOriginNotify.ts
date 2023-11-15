// Auto Generated, do not edit.
import { Read } from "../../stream";
import * as ReadNBytesInt64 from "../../common/ReadNBytesInt64";
export type PKTStatChangeOriginNotify = {
  objectId: bigint;
  unk1: number;
  unk3_0?: number;
  unk4: { statType: number; value: bigint }[];
  statPairChangedList: { statType: number; value: bigint }[];
};
export function read(buf: Buffer) {
  const reader = new Read(buf);
  const data = {} as PKTStatChangeOriginNotify;
  data.objectId = reader.u64();
  data.unk1 = reader.u8();
  if (reader.bool()) data.unk3_0 = reader.u32();
  data.unk4 = reader.array(
    reader.u16(),
    () => {
      const a = {} as { statType: number; value: bigint };
      a.statType = reader.u8();
      a.value = ReadNBytesInt64.read(reader);
      return a;
    },
    153
  );
  data.statPairChangedList = reader.array(
    reader.u16(),
    () => {
      const b = {} as { statType: number; value: bigint };
      b.statType = reader.u8();
      b.value = ReadNBytesInt64.read(reader);
      return b;
    },
    153
  );
  return data;
}
export const name = "PKTStatChangeOriginNotify";
export const opcode = 28295;
