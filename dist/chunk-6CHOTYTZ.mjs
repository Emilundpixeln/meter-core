import{TypedEmitter as hn}from"tiny-typed-emitter";var n=class{b;o;constructor(t){this.b=t,this.o=0}skip(t=0){this.o+=t}bool(){return this.u8()===1}u8(){return this.b.readUint8(this.o++)}i8(){return this.b.readInt8(this.o++)}u16(){let t=this.b.readUint16LE(this.o);return this.o+=2,t}i16(){let t=this.b.readInt16LE(this.o);return this.o+=2,t}u32(){let t=this.b.readUint32LE(this.o);return this.o+=4,t}i32(){let t=this.b.readInt32LE(this.o);return this.o+=4,t}f32(){let t=this.b.readFloatLE(this.o);return this.o+=4,t}u64(){let t=this.b.readBigUint64LE(this.o);return this.o+=8,t}i64(){let t=this.b.readBigInt64LE(this.o);return this.o+=8,t}string(t){let o=this.u16();if(o<=t){o=o*2;let r=this.b.toString("utf16le",this.o,this.o+o);return this.o+=o,r}return""}bytes(t=0,o,r){if(o&&t>o)return Buffer.alloc(0);r&&(t=t*r);let a=Buffer.from(this.b.subarray(this.o,this.o+t));return this.o+=t,a}array(t,o,r){return r&&t>r?[]:new Array(t).fill(void 0).map(o)}},_o=class{b;o;constructor(t=65535){this.b=Buffer.allocUnsafe(t),this.o=0}get value(){return this.b.subarray(0,this.o)}skip(t=0){this.o+=t}bool(t=!1){return this.u8(t?1:0),t}u8(t=0){this.b.writeUInt8(t,this.o++)}i8(t=0){this.b.writeInt8(t,this.o++)}u16(t=0){this.o=this.b.writeUInt16LE(t,this.o)}i16(t=0){this.o=this.b.writeInt16LE(t,this.o)}u32(t=0){this.o=this.b.writeUInt32LE(t,this.o)}i32(t=0){this.o=this.b.writeInt32LE(t,this.o)}f32(t=0){this.o=this.b.writeFloatLE(t,this.o)}u64(t=0n){this.o=this.b.writeBigUInt64LE(BigInt(t),this.o)}i64(t=0n){this.o=this.b.writeBigInt64LE(BigInt(t),this.o)}string(t="",o=0){this.u16(t.length),t.length<=o&&(this.o+=this.b.write(t,this.o,"utf16le"))}bytes(t=Buffer.alloc(0),o={}){if(o.maxLen){let r=o.multiplier??1;if(t.length%r)throw new Error(`Error writing bytes, chunkSize should be a multiple of intut value size, got ${t.length}%${r}`);let a=t.length/r;if(a>o.maxLen)throw new Error(`Error writing bytes, input value size exceeded maxLen, got ${a} > ${o.maxLen}`);if(!o.lenType)throw new Error(`Error writing bytes, invalid lenType when writing chunks, got ${o.lenType}`);this[o.lenType](a)}else if(o.length&&t.length!==o.length)throw new Error(`Error writing bytes, input value size doesn't match opts.length, ${t.length} !== ${o.lenType}`);this.o+=t.copy(this.b,this.o)}array(t=[],o,r){if(t===void 0||t.length>o.maxLen){this[o.lenType](0);return}this[o.lenType](t.length),t.forEach(r)}};function b(e){let t={};return t.id=e.u32(),t.points=e.u16(),t.level=e.u8(),t}function D(e){let t=new n(e),o={};return o.abilityDataList=t.array(t.u16(),()=>b(t),100),o}var h="PKTAbilityChangeNotify",R=28113;function vo(e){let t={};return t.featureType=e.u16(),t.level=e.u32(),t}function B(e){let t=new n(e),o={};return o.activeAbilityList=t.array(t.u16(),()=>vo(t),60),o.objectId=t.u64(),o}var A="PKTActiveAbilityNotify",L=41991;function C(e){let t=new n(e),o={};return o.addonFeatureIdList=t.bytes(t.u16(),200,4),o.addonSkillFeatureList=t.array(t.u16(),()=>{let r={};return r.skillId=t.u32(),r.addonSkillFeatureIdList=t.array(t.u16(),()=>t.u32(),5),r},200),o.objectId=t.u64(),o}var w="PKTAddonSkillFeatureChangeNotify",M=25550;function j(e){let t=new n(e),o={};return o.packetResultCode=t.u32(),o.unk1_m=t.bytes(t.u32(),688),o}var F="PKTAuthTokenResult",U=33150;function O(e){let t=new n(e),o={};return o.paralyzationMaxPoint=t.u32(),o.objectId=t.u64(),o.paralyzationPoint=t.u32(),o.type=t.u8(),t.skip(1),o}var q="PKTBlockSkillStateNotify",z=48017;function V(e){let t=new n(e),o={};return t.skip(1),o.targetId=t.u64(),t.skip(1),o.type=t.u32(),o.sourceId=t.u64(),o}var Z="PKTCounterAttackNotify",H=40936;function G(e){let t=new n(e),o={};return t.bool()&&(o.unk1_0=t.u8()),o.unk2=t.u64(),o.unk3=t.u16(),t.bool()&&(o.unk5_0=t.u8()),o.targetId=t.u64(),o.unk7=t.u32(),t.bool()&&(o.unk9_0=t.u8()),o.unk10=t.u8(),o.sourceId=t.u64(),o.unk12=t.u32(),o}var W="PKTDeathNotify",Y=32951;var nn=[0,31,28,31,30,31,30,31,31,30,31,30,31];function rn(e){return!(e%4||!(e%100)&&e%400)}function un(e,t,o){if(e>99){if(e<1752||e==1752&&(t<9||t==9&&o<<14))return!1}else e+=1900;return o>0&&t<=12&&(o<=nn[t]||o==29&&t==2&&rn(e))}function $(e){let t=Number(e&0xffffffffn),o=Number(e>>32n&0xffffffffn),r=t&4095,a=(t&65535)>>12,f=t>>16&31;un(r,a,f)||(r=a=f=0);let m=t>>21&31,T=t>>26&63,P=o&63,v=o>>6&16383;return m<24&&T<60&&P<60&&v<1e3||(m=24,T=P=v=0),new Date(Date.UTC(r<=99?r+1900:r,a-1,f,m,T,P,v))}function Eo(e){let t=0n;return t|=BigInt(e.getUTCMilliseconds())<<38n,t|=BigInt(e.getUTCSeconds())<<32n,t|=BigInt(e.getUTCMinutes())<<26n,t|=BigInt(e.getUTCHours())<<21n,t|=BigInt(e.getUTCDate())<<16n,t|=BigInt(e.getUTCMonth()+1)<<12n,t|=BigInt(e.getUTCFullYear()<2e3?e.getUTCFullYear()-1900:e.getUTCFullYear()),t}function p(e,t=0){let o=e.u16();return(o&4095)<2079?(e.o-=2,$(e.i64())):$(BigInt(o)&0xfffn|0x11000n)}function Hn(e,t=$(0x1181fn)){t.getUTCFullYear()>=2079?e.u16(Number(Eo(t)&0xffffn)):e.i64(Eo(t))}function d(e){let t={};return t.level=e.u16(),t.expireTime=p(e),t.id=e.u32(),t.slot=e.u16(),e.bool()&&(t.unk5_0=e.u8()),t.itemTint=e.bytes(e.u16(),3,14),t}function J(e){let t=new n(e),o={};return o.unk0=t.u32(),o.unk1=t.u32(),o.objectId=t.u64(),o.equipItemDataList=t.array(t.u16(),()=>d(t),32),o}var Q="PKTEquipChangeNotify",X=23318;function tt(e){let t=new n(e),o={};return o.equipLifeToolDataList=t.array(t.u16(),()=>d(t),9),o.objectId=t.u64(),o}var et="PKTEquipLifeToolChangeNotify",ot=48579;function nt(e){let t=new n(e),o={};return t.skip(1),o.objectId=t.u64(),t.skip(1),o.stance=t.u8(),o}var rt="PKTIdentityStanceChangeNotify",ut=44184;function at(e){let t=new n(e),o={};return o.abilityDataList=t.array(t.u16(),()=>b(t),100),o.struct_130=t.bytes(t.u16(),348,48),o}var it="PKTInitAbility",st=44384;function ft(e){let t=new n(e),o={};return o.struct_574=t.string(128),o.playerId=t.u64(),o.unk2=t.u64(),o.unk3=t.u32(),o.unk4=t.u8(),o.lostArkDateTime=p(t),o.struct_30=t.array(t.u16(),()=>{let r={};return r.struct_560=t.string(32),r.struct_574=t.string(128),r.versionString=t.string(64),r},64),o.unk7=t.u32(),o}var mt="PKTInitEnv",ct=45410;function i(e){let t={};return e.bool()&&(t.unk1_0=e.u64()),e.bool()&&(t.value=e.bytes(16)),t.occurTime=p(e),t.struct_441=e.bytes(e.u16(),8,7),t.skillLevel=e.u8(),t.stackCount=e.u8(),t.effectInstanceId=e.u32(),t.statusEffectId=e.u32(),t.sourceId=e.u64(),t.endTick=e.u64(),t.totalTime=e.f32(),t}function an(e){if(e.length===0)return 0n;if(e.length>8)throw new Error("Value is too large");let t=Buffer.alloc(8);return e.copy(t),t.readBigInt64LE()}function u(e,t=0){let o=e.u8(),r=e.bytes(o>>1&7),a=an(r)<<4n|BigInt(o>>4);return o&1?-a:a}function nr(e,t=0n){let o=Buffer.alloc(8),r=t<0n;o.writeBigInt64LE((r?-t:t)>>4n);let a=0;for(let[f,m]of o.entries())m!=0&&(a=f+1);if(a>7)throw new Error("Value is too large");e.u8(Number((r?-t:t)&0xfn)<<4|(a&7)<<1|(r?1:0)),e.bytes(o.subarray(0,a),{length:a})}function k(e){let t={};return t.unk0=e.u64(),t.unk1=u(e),t.unk2=u(e),t.unk3=e.u8(),t.unk4=e.u8(),t.unk5=e.u16(),t.unk6=e.u8(),t}function dt(e){let t=new n(e),o={};return o.unk0=t.u32(),o.unk1=t.u16(),o.unk2=t.u8(),o.unk3=t.u32(),o.unk4=t.u16(),o.unk5=t.u8(),o.unk6=t.u8(),o.unk7=t.u16(),o.unk8=t.u8(),o.unk9=t.u32(),o.unk10=t.u32(),o.unk11=t.u32(),o.unk12=t.u16(),t.bool()&&(o.unk14_0=t.u32()),o.classId=t.u16(),o.unk16=t.u32(),o.statusEffectDatas=t.array(t.u16(),()=>i(t),80),o.unk18=t.bytes(25),o.struct_336=t.string(7),o.statPair=t.array(t.u16(),()=>{let r={};return r.statType=t.u8(),r.value=u(t),r},152),o.unk21=t.u8(),o.periodUpdateStatDataList=t.array(t.u16(),()=>k(t),5),o.unk23=t.u8(),o.unk24=t.u8(),o.unk25=t.u32(),o.unk26=t.u64(),o.struct_223=t.bytes(t.u16(),3,17),o.unk28=t.u8(),o.unk29=t.bytes(35),o.unk30=t.u32(),o.unk31=t.u8(),o.unk32=t.u32(),o.gearLevel=t.f32(),o.unk34=t.u8(),o.unk35=t.u8(),o.characterId=t.u64(),o.unk37=t.u32(),o.unk38=t.u64(),o.unk39=t.bytes(120),o.unk40=t.u8(),o.struct_342=t.bytes(t.u16(),104,30),o.unk42=t.u8(),o.unk43=t.u8(),o.unk44=t.u8(),o.level=t.u16(),o.unk46=t.u8(),o.playerId=t.u64(),o.unk48=t.u32(),o.unk49=t.u64(),o.unk50=t.u8(),o.unk51=t.u32(),o.unk52=t.u8(),o.unk53=t.u8(),o.unk54=t.u64(),o.name=t.string(20),o.unk56=t.u8(),o.struct_99=t.bytes(t.u16(),58),o}var lt="PKTInitPC",yt=9180;function Do(e){let t={},o=e.u16();return o===1&&(t.unk1_0=e.bytes(o)),t}function ho(e){let t={};return t.unk0=e.u8(),t.struct_140=e.bytes(e.u16(),3,9),t.unk2=e.u8(),t.struct_139=Do(e),t.unk4=e.u8(),t.unk5=e.u32(),t.unk6=e.u32(),t.unk7=e.u8(),t}function Ro(e){let t={};return t.unk0=e.u32(),t.unk1=e.u16(),t.unk2=e.u32(),t.unk3=e.u32(),t.struct_235=e.bytes(e.u16(),10,18),t.struct_487=e.bytes(e.u16(),10,9),t.unk6=e.u32(),t.struct_389=e.bytes(e.u16(),2,10),t.struct_233=e.array(e.u16(),()=>ho(e),3),t.unk9=e.u32(),t.struct_258=e.bytes(e.u16(),2,9),t.unk11=e.u64(),t.unk12=e.u8(),t.unk13=e.u32(),t}function Bo(e){let t={};return t.unk0=e.u32(),t.struct_436=e.bytes(e.u16(),3,10),t.unk2=e.u32(),t.struct_237=e.bytes(e.u16(),10,29),e.bool()&&(t.unk1_0=e.u32(),t.unk1_1=e.u32(),t.struct_185=e.bytes(e.u16(),5,30)),t.unk5=e.u32(),t.struct_269=e.bytes(e.u16(),3,21),t.unk7=e.u32(),t.struct_231=e.bytes(e.u16(),3,7),e.bool()&&(t.struct_228=e.bytes(e.u16(),2,32)),t.itemTint=e.bytes(e.u16(),3,14),e.bool()&&(t.unk13_0=e.bytes(9)),t.unk14=e.u32(),t.unk15=e.u32(),t.unk16=e.u8(),t}function Ao(e){let t={};return t.struct_0=e.array(e.u16(),()=>{let o={};return o.unk1_0_0=e.u32(),o.struct_515=e.bytes(e.u16(),10),o},3),t.unk1=e.u8(),t.struct_126=e.bytes(e.u16(),3,5),t.unk3=e.u8(),t.unk4=e.u32(),t}function Lo(e){let t={};return t.struct_23=e.array(e.u16(),()=>{let o={};return o.unk1_0_0=e.u16(),o.unk1_0_1=e.u8(),o.struct_230=e.string(2),o},20),t.struct_231=e.bytes(e.u16(),3,7),t.unk2=e.u8(),t.unk3=e.u8(),t.struct_232=e.bytes(e.u16(),5,7),t.unk5=e.u8(),t}function Co(e){let t={},o=e.u8();return o===1&&(t.struct_643=Ro(e)),o===2&&(t.struct_1=e.array(e.u16(),()=>{let r={};return r.unk1_0_0=e.u32(),r.unk1_0_1=e.u8(),r.unk1_0_2=e.u8(),r.struct_515=e.bytes(e.u16(),10),r},3),t.unk2_1=e.u8(),t.struct_125=e.bytes(e.u16(),3,6)),o===3&&(t.unk3_0=e.bytes(26)),o===4&&(t.unk4_0=e.u32(),t.unk4_1=e.bytes(e.u16(),10,13),t.unk4_2=e.bytes(e.u16(),10,13)),o===5&&(t.struct_642=Bo(e)),o===6&&(t.struct_586=Ao(e)),o===7&&(t.unk7_0=e.bytes(9)),o===8&&(t.struct_636=Lo(e)),t}function wo(e){let t={};return e.u32()>0&&(t.serialNumber=e.u64(),t.id=e.u32(),t.level=e.u16(),t.slot=e.u16(),t.durability=e.u32(),t.unk1_6_m=e.u32(),t.flag=e.u32(),t.expireTime=p(e),t.lockUpdateTime=p(e),e.bool()&&(t.unk1_10_0=e.bytes(9)),t.unk1_11=e.u8(),t.unk1_12=e.u8(),t.unk1_13=e.u32(),t.struct_533=Co(e),t.unk1_15=e.u32()),t}function bt(e){let t=new n(e),o={};return o.itemDataList=t.array(t.u16(),()=>wo(t),80),o.storageType=t.u8(),o}var kt="PKTInitItem",Tt=44970;function Mo(e){let t={};return t.unk0=e.u32(),t.unk1=e.u32(),e.bool()&&(t.unk3_0=e.bytes(9)),t.unk4=e.u32(),e.bool()&&(t.unk6_0=e.u32()),t}function Pt(e){let t=new n(e),o={};return o.unk0=t.u8(),o.abilityDataList=t.array(t.u16(),()=>b(t),100),o.unk2=t.u64(),o.struct_223=t.bytes(t.u16(),3,17),o.unk4=t.u8(),o.unk5=t.u32(),t.bool()&&(o.unk7_0=t.u32()),o.struct_342=t.bytes(t.u16(),104,30),o.struct_130=t.bytes(t.u16(),348,48),o.addonFeatureIdList=t.bytes(t.u16(),200,4),o.unk11=t.u64(),o.struct_419=t.array(t.u16(),()=>Mo(t),300),o.statusEffectDatas=t.array(t.u16(),()=>i(t),80),o.addonSkillFeatureList=t.array(t.u16(),()=>{let r={};return r.skillId=t.u32(),r.addonSkillFeatureIdList=t.array(t.u16(),()=>t.u32(),5),r},200),o.unk15=t.u8(),o.statPair=t.array(t.u16(),()=>{let r={};return r.statType=t.u8(),r.value=u(t),r},152),o}var xt="PKTInitLocal",gt=9337;function St(e){let t=new n(e),o={};return o.account_CharacterId1=t.u64(),o.unk1=t.u32(),o.serverAddr=t.string(256),o.account_CharacterId2=t.u64(),o}var Kt="PKTMigrationExecute",It=21739;function jo(e){let t={};return t.unk0=e.u8(),t.unk1=e.u8(),t.equipItemDataList=e.array(e.u16(),()=>d(e),32),t.lookData=e.bytes(e.u32(),512),t.unk4=e.u64(),t.unk5=e.u8(),t.unk6=e.u16(),t.lostArkString=e.string(20),t}function Nt(e){return e>>20===1?-((~e>>>0)+1&2097151):e}function s(e,t=0){let o=e.u64();return{x:Nt(Number(o&0x1fffffn)),y:Nt(Number(o>>21n&0x1fffffn)),z:Nt(Number(o>>42n&0x1fffffn))}}function pr(e,t={x:0,y:0,z:0}){e.u64(BigInt(Math.round(t.x??0)>>>0&2097151)|BigInt(Math.round(t.y??0)>>>0&2097151)<<21n|BigInt(Math.round(t.z??0)>>>0&2097151)<<42n)}function l(e,t=0){return e.u16()*(2*Math.PI)/65536}function dr(e,t=0){e.u16(Math.round(t*65536/(2*Math.PI))%65536)}function K(e){let t={};return t.statusEffectDatas=e.array(e.u16(),()=>i(e),80),e.bool()&&(t.transitIndex=e.u32()),e.bool()&&(t.struct_337=e.bytes(e.u16(),11,9)),e.bool()&&(t.unk6_0=e.u8()),e.bool()&&(t.balanceLevel=e.u16()),t.unk9=e.u8(),t.objectId=e.u64(),t.unk11=e.u8(),t.unk12=e.u8(),t.periodUpdateStatDataList=e.array(e.u16(),()=>k(e),5),e.bool()&&(t.unk15_0=e.u8()),t.unk16=e.u8(),e.bool()&&(t.unk18_0=e.u8()),t.typeId=e.u32(),e.bool()&&(t.unk21_0=e.u8()),e.bool()&&(t.struct_711=jo(e)),t.statPair=e.array(e.u16(),()=>{let o={};return o.statType=e.u8(),o.value=u(e),o},152),t.spawnIndex=e.u32(),e.bool()&&(t.unk27_0=e.u8()),e.bool()&&(t.struct_270=e.bytes(e.u16(),12,12)),t.position=s(e),t.unk31=e.u8(),e.bool()&&(t.unk33_0=e.u32()),e.bool()&&(t.unk35_0=e.u64()),e.bool()&&(t.unk37_0=e.u32()),e.bool()&&(t.unk39_0=e.u8()),t.directionYaw=l(e),e.bool()&&(t.unk42_0=e.u16()),t.unk43=e.u8(),e.bool()&&(t.unk45_0=e.u8()),t.level=e.u16(),e.bool()&&(t.unk48_0=e.u32()),e.bool()&&(t.unk50_0=e.u32()),t}function vt(e){let t=new n(e),o={};return o.npcStruct=K(t),t.bool()&&(o.unk2_0=t.u8()),t.bool()&&(o.unk1_0=t.string(20),o.unk1_1=t.string(20)),o.unk4=t.u8(),t.bool()&&(o.unk6_0=t.u64()),o}var Et="PKTNewNpc",Dt=17856;function ht(e){let t=new n(e),o={};return o.publishReason=t.u8(),t.skip(27),o.ownerId=t.u64(),t.skip(4),o.npcData=K(t),o}var Rt="PKTNewNpcSummon",Bt=37613;function Uo(e){let t={};return t.unk0=e.u32(),t.unk1=e.u32(),e.bool()&&(t.unk3_0=e.bytes(12)),t.unk4=e.bytes(12),t}function Oo(e){let t={};return t.rvRLevel=e.u16(),t.unk32_m=e.u8(),t.unk17_m=e.u8(),t.unk1_m=e.u8(),t.classId=e.u16(),t.unk23_m=e.u8(),t.unk2_m=e.u8(),t.guildId=e.u32(),t.characterId=e.u64(),t.secondHonorTitleId=e.u16(),t.unk28_m=e.u8(),t.unk5_m=e.u32(),t.avatarHide=e.u8(),t.firstHonorTitleId=e.u16(),t.identityData=e.bytes(25),t.unk15=e.u32(),t.unk16=e.u8(),t.position=s(e),t.statusEffectDatas=e.array(e.u16(),()=>i(e),80),t.lookData=e.bytes(e.u32(),512),t.addonSkillFeatureList=e.array(e.u16(),()=>{let o={};return o.skillId=e.u32(),o.addonSkillFeatureIdList=e.array(e.u16(),()=>e.u32(),5),o},200),t.addonFeatureIdList=e.bytes(e.u16(),200,4),t.unk29_m=e.u8(),t.equipLifeToolDataList=e.array(e.u16(),()=>d(e),9),t.petId=e.u32(),e.bool()&&(t.grabbedData=e.bytes(12)),t.unk0_m=e.bytes(5),t.heading=l(e),t.equipItemDataList=e.array(e.u16(),()=>d(e),32),t.guildName=e.string(20),t.playerId=e.u64(),t.statPair=e.array(e.u16(),()=>{let o={};return o.statType=e.u8(),o.value=u(e),o},152),t.level=e.u16(),t.avgItemLevel=e.f32(),t.worldId=e.u8(),t.maxItemLevel=e.f32(),t.unk45_m=e.u32(),t.unk15_m=e.u8(),t.unk39=e.u32(),t.name=e.string(20),t.unk7_m=e.u32(),t.unk42=e.u32(),t.unk4_m=e.u32(),t.periodUpdateStatDataList=e.array(e.u16(),()=>k(e),5),t.unk25_m=e.u8(),t}function At(e){let t=new n(e),o={};return t.bool()&&(o.unk5_0_m=t.bytes(20)),o.unk0_m=t.u8(),t.bool()&&(o.unk4_0_m=t.bytes(12)),t.bool()&&(o.unk3_0_m=t.u32()),o.unk2_m=t.u8(),t.bool()&&(o.trackMoveInfo=Uo(t)),o.pcStruct=Oo(t),o}var Lt="PKTNewPC",Ct=58825;function I(e,t=0){return{first:e.u8(),second:e.u8(),third:e.u8()}}function qo(e,t){e.u8(t.first),e.u8(t.second),e.u8(t.third)}function N(e,t=0){return{first:e.u16(),second:e.u16(),third:e.u16()}}function Vo(e,t){e.u16(t.first),e.u16(t.second),e.u16(t.third)}function Ho(e){let t={};return t.ownerId=e.u64(),e.bool()&&(t.struct_337=e.bytes(e.u16(),11,9)),t.tripodIndex=I(e),t.unk4=e.u32(),t.unk5=e.u16(),t.skillEffect=e.u32(),t.unk7=e.u64(),t.unk8=e.u16(),t.projectileId=e.u64(),t.skillLevel=e.u8(),t.targetObjectId=e.u64(),t.unk12=e.u64(),e.bool()&&(t.unk14_0=e.u32()),t.unk15=e.u8(),t.unk16=e.u32(),t.unk17=e.u8(),t.chainSkillEffect=e.u32(),t.tripodLevel=N(e),t.unk20=e.u32(),t.skillId=e.u32(),e.bool()&&(t.unk23_0=e.u64()),t}function wt(e){let t=new n(e),o={};return o.projectileInfo=Ho(t),o}var Mt="PKTNewProjectile",jt=6374;function Ft(e){let t=new n(e),o={};return o.paralyzationPoint=t.u32(),o.hitCheckTime=t.u32(),o.paralyzationMaxPoint=t.u32(),t.skip(1),o.noHitCheckTime=t.u32(),o.decreasePoint=t.u32(),t.skip(2),o.objectId=t.u64(),o.enable=t.bool(),o}var Ut="PKTParalyzationStateNotify",Ot=43721;function Go(e){let t={};return t.classId=e.u16(),t.characterId=e.u64(),t.position=s(e),t.unk3=e.u8(),t.partyMemberNumber=e.u8(),t.curHp=u(e),t.maxHp=u(e),t.unk7=e.u8(),t.unk8=e.u8(),t.transitIndex=e.u32(),t.unk10=e.u8(),t.name=e.string(20),t.unk12=e.u16(),t.characterLevel=e.u16(),t.unk14=e.u8(),t.zoneId=e.u32(),t.worldId=e.u8(),t.zoneInstId=e.u64(),t.auths=e.u8(),t.gearLevel=e.f32(),t}function qt(e){let t=new n(e),o={};return o.partyLootType=t.u8(),o.partyInstanceId=t.u32(),o.lootGrade=t.u32(),o.memberDatas=t.array(t.u16(),()=>Go(t),40),o.partyType=t.u8(),o.raidInstanceId=t.u32(),o}var zt="PKTPartyInfo",Vt=23785;function Zt(e){let t=new n(e),o={};return o.name=t.string(20),o.partyInstanceId=t.u32(),o.partyLeaveType=t.u8(),o}var Ht="PKTPartyLeaveResult",Gt=24901;function Wt(e){let t=new n(e),o={};return o.objectId=t.u64(),o.passiveStatusEffectList=t.array(t.u16(),()=>t.u32(),10),o.unk0_m=t.u8(),o}var Yt="PKTPartyPassiveStatusEffectAddNotify",$t=11947;function Jt(e){let t=new n(e),o={};return o.objectId=t.u64(),o.passiveStatusEffectList=t.array(t.u16(),()=>t.u32(),10),o}var Qt="PKTPartyPassiveStatusEffectRemoveNotify",Xt=45831;function te(e){let t=new n(e),o={};return o.unk0=t.u64(),o.unk1=t.u8(),o.statusEffectDatas=t.array(t.u16(),()=>i(t),80),o.playerIdOnRefresh=t.u64(),o.characterId=t.u64(),o}var ee="PKTPartyStatusEffectAddNotify",oe=43746;function ne(e){let t=new n(e),o={};return o.unk0=t.u64(),o.reason=t.u8(),o.statusEffectIds=t.array(t.u16(),()=>t.u32(),80),o.characterId=t.u64(),o}var re="PKTPartyStatusEffectRemoveNotify",ue=56510;function ae(e){let t=new n(e),o={};return o.raidInstanceId=t.u32(),t.skip(9),o.partyInstanceId=t.u32(),t.skip(14),o.characterId=t.u64(),t.skip(4),o}var ie="PKTPartyStatusEffectResultNotify",se=11558;function fe(e){let t=new n(e),o={};return o.passiveStatusEffectList=t.array(t.u16(),()=>t.u32(),10),o}var me="PKTPassiveStatusEffectAddNotify",ce=34518;function pe(e){let t=new n(e),o={};return o.passiveStatusEffectList=t.array(t.u16(),()=>t.u32(),10),o}var de="PKTPassiveStatusEffectRemoveNotify",le=42313;function ye(e){let t=new n(e),o={};return o.unk0=t.bytes(7),o}var be="PKTRaidBossKillNotify",ke=58014;function Te(e){let t=new n(e),o={};return o.unk0=t.u64(),o.unk1=t.u8(),o.unk2=t.u64(),o.unk3=t.u8(),o.unk4=t.u8(),o.struct_50=t.array(t.u16(),()=>{let r={};return r.unk1_0_0=u(t),r.struct_521=t.bytes(t.u16(),3),r.unk1_0_2=u(t),r.unk1_0_3=t.u32(),r},3),o.unk6=t.u64(),o.unk7=t.u64(),o}var Pe="PKTRaidResult",xe=14870;function Wo(e){let t={};return t.objectId=e.u64(),t.unpublishReason=e.u8(),t}function ge(e){let t=new n(e),o={};return o.unpublishedObjects=t.array(t.u16(),()=>Wo(t),200),o}var Se="PKTRemoveObject",Ke=31334;function Ie(e){let t=new n(e),o={};return t.skip(2),o.skillLevel=t.u8(),t.skip(1),o.caster=t.u64(),o.skillId=t.u32(),o}var Ne="PKTSkillCastNotify",_e=3108;function Yo(e,t=0){let o={},r=e.u8();return r&1&&(o.moveTime=e.u32()),r&2&&(o.standUpTime=e.u32()),r&4&&(o.downTime=e.u32()),r&8&&(o.freezeTime=e.u32()),r&16&&(o.moveHeight=e.u32()),r&32&&(o.farmostDist=e.u32()),r&64&&(o.flag40=e.bytes(e.u16(),6)),o}function $r(e,t){let o=(t.moveTime===void 0?0:1)|(t.standUpTime===void 0?0:2)|(t.downTime===void 0?0:4)|(t.freezeTime===void 0?0:8)|(t.moveHeight===void 0?0:16)|(t.farmostDist===void 0?0:32)|(t.flag40===void 0?0:64);e.u8(o),o&1&&e.u32(t.moveTime),o&2&&e.u32(t.standUpTime),o&4&&e.u32(t.downTime),o&8&&e.u32(t.freezeTime),o&16&&e.u32(t.moveHeight),o&32&&e.u32(t.farmostDist),o&64&&e.bytes(t.flag40,{maxLen:6,lenType:"u16"})}function _(e){let t={};return t.unk3_m=e.u16(),t.damageType=e.u8(),t.maxHp=u(e),e.bool()&&(t.damageAttr=e.u8()),t.modifier=e.u8(),t.targetId=e.u64(),t.curHp=u(e),t.damage=u(e),t}function Jo(e){let t={};return t.unk2_m=e.u64(),t.destination=s(e),t.position=s(e),t.skillMoveOptionData=Yo(e),t.skillDamageEvent=_(e),t.unk8_m=e.u16(),t.unk4_m=e.u16(),t.unk1_m=e.u8(),t.unk3_m=e.u16(),t}function ve(e){let t=new n(e),o={};return o.sourceId=t.u64(),o.unk2_m=t.u32(),o.skillDamageAbnormalMoveEvents=t.array(t.u16(),()=>Jo(t),50),o.unk1_m=t.u8(),o.skillEffectId=t.u32(),o.skillId=t.u32(),o}var Ee="PKTSkillDamageAbnormalMoveNotify",De=5852;function he(e){let t=new n(e),o={};return o.skillLevel=t.u8(),o.skillId=t.u32(),o.skillEffectId=t.u32(),o.sourceId=t.u64(),o.skillDamageEvents=t.array(t.u16(),()=>_(t),50),o}var Re="PKTSkillDamageNotify",Be=10750;function Ae(e){let t=new n(e),o={};return t.skip(40),o.skillId=t.u32(),o.stage=t.u8(),o.sourceId=t.u64(),o}var Le="PKTSkillStageNotify",Ce=53055;function Qo(e,t=0){let o={},r=e.u8();return r&1&&(o.layerIndex=e.u8()),r&2&&(o.startStageIndex=e.u8()),r&4&&(o.transitIndex=e.u32()),r&8&&(o.stageStartTime=e.u32()),r&16&&(o.farmostDistance=e.u32()),r&32&&(o.tripodIndex=I(e)),r&64&&(o.tripodLevel=N(e)),o}function nu(e,t){let o=(t.layerIndex===void 0?0:1)|(t.startStageIndex===void 0?0:2)|(t.transitIndex===void 0?0:4)|(t.stageStartTime===void 0?0:8)|(t.farmostDistance===void 0?0:16)|(t.tripodIndex===void 0?0:32)|(t.tripodLevel===void 0?0:64);e.u8(o),o&1&&e.u8(t.layerIndex),o&2&&e.u8(t.startStageIndex),o&4&&e.u32(t.transitIndex),o&8&&e.u32(t.stageStartTime),o&16&&e.u32(t.farmostDistance),o&32&&qo(e,t.tripodIndex),o&64&&Vo(e,t.tripodLevel)}function we(e){let t=new n(e),o={};return o.skillOptionData=Qo(t),o.skillLevel=t.u8(),t.bool()&&(o.aiStateId=t.u32()),t.bool()&&(o.pitchRotation=l(t)),o.sourceId=t.u64(),o.curPosition=s(t),o.newPosition=s(t),t.bool()&&(o.unk1_m=t.u32()),o.curDirectionYaw=l(t),o.skillId=t.u32(),o.aimTargetPosition=s(t),o.newDirectionYaw=l(t),o}var Me="PKTSkillStartNotify",je=26713;function Fe(e){let t=new n(e),o={};return o.objectId=t.u64(),t.bool()&&(o.unk2_0=t.u32()),o.unk3=t.u8(),o.statPairChangedList=t.array(t.u16(),()=>{let r={};return r.statType=t.u8(),r.value=u(t),r},152),o.unk5=t.array(t.u16(),()=>{let r={};return r.statType=t.u8(),r.value=u(t),r},152),o}var Ue="PKTStatChangeOriginNotify",Oe=1877;function qe(e){let t=new n(e),o={};return t.bool()&&(o.unk1_0=t.u64()),o.new=t.bool(),o.unk3=t.u64(),o.objectId=t.u64(),o.statusEffectData=i(t),o}var ze="PKTStatusEffectAddNotify",Ve=15270;function Ze(e){let t=new n(e),o={};return o.objectId=t.u64(),o.statusEffectIds=t.array(t.u16(),()=>t.u32(),80),o.reason=t.u8(),o}var He="PKTStatusEffectRemoveNotify",Ge=12016;function We(e){let t=new n(e),o={};return o.targetId=t.u64(),o.effectInstanceId=t.u32(),t.skip(1),o.expirationTick=t.u64(),t.skip(2),o}var Ye="PKTStatusEffectDurationNotify",$e=23329;function Je(e){let t=new n(e),o={};return o.characterId=t.u64(),t.skip(2),o.objectId=t.u64(),o.effectInstanceId=t.u32(),t.skip(1),o.value=t.u32(),t.skip(4),o}var Qe="PKTStatusEffectSyncDataNotify",Xe=18697;function to(e){let t=new n(e),o={};return o.triggerId=t.u32(),o.unk2_m=t.bool(),t.skip(2),o.step=t.u32(),o}var eo="PKTTriggerBossBattleStatus",oo=31690;function no(e){let t=new n(e),o={};return o.involvedPCs=t.array(t.u16(),()=>t.u64(),40),o.packetResultCode=t.u32(),o.triggerId=t.u32(),o.unk0_m=t.u32(),o}var ro="PKTTriggerFinishNotify",uo=55562;function ao(e){let t=new n(e),o={};return o.triggerId=t.u32(),o.sourceId=t.u64(),o.triggerSignalType=t.u32(),o.involvedPCs=t.array(t.u16(),()=>t.u64(),40),o}var io="PKTTriggerStartNotify",so=41810;function fo(e){let t=new n(e),o={};return o.curHp=u(t),o.characterId=t.u64(),o.position=t.u64(),o.statusEffectDatas=t.array(t.u16(),()=>i(t),80),o.maxHp=u(t),o.unk0_m=t.u32(),o}var mo="PKTTroopMemberUpdateMinNotify",co=21300;function po(e){let t=new n(e),o={};return t.skip(1),o.identityGauge1=t.u32(),o.identityGauge2=t.u32(),o.identityGauge3=t.u32(),o.playerId=t.u64(),t.skip(1),o}var lo="PKTIdentityGaugeChangeNotify",yo=48079;function bo(e){let t=new n(e),o={};return t.skip(1),o.objectId=t.u64(),t.skip(1),o}var ko="PKTZoneObjectUnpublishNotify",To=6281;function Xo(e){let t={};return t.instanceId=e.u64(),t.target=e.u8(),t.stackCount=e.u8(),t.id=e.u32(),t}function Po(e){let t=new n(e),o={};return o.zoneStatusEffectDataList=t.array(t.u16(),()=>Xo(t),4),o}var xo="PKTZoneStatusEffectAddNotify",go=29344;function So(e){let t=new n(e),o={};return t.skip(1),o.statusEffectId=t.u32(),o}var Ko="PKTZoneStatusEffectRemoveNotify",Io=20478;var tn=new Map([[R,[h,D]],[L,[A,B]],[M,[w,C]],[U,[F,j]],[z,[q,O]],[H,[Z,V]],[Y,[W,G]],[X,[Q,J]],[ot,[et,tt]],[ut,[rt,nt]],[st,[it,at]],[ct,[mt,ft]],[yt,[lt,dt]],[Tt,[kt,bt]],[gt,[xt,Pt]],[It,[Kt,St]],[Dt,[Et,vt]],[Bt,[Rt,ht]],[Ct,[Lt,At]],[jt,[Mt,wt]],[Ot,[Ut,Ft]],[Vt,[zt,qt]],[Gt,[Ht,Zt]],[$t,[Yt,Wt]],[Xt,[Qt,Jt]],[oe,[ee,te]],[ue,[re,ne]],[se,[ie,ae]],[ce,[me,fe]],[le,[de,pe]],[ke,[be,ye]],[xe,[Pe,Te]],[Ke,[Se,ge]],[_e,[Ne,Ie]],[De,[Ee,ve]],[Be,[Re,he]],[Ce,[Le,Ae]],[je,[Me,we]],[Oe,[Ue,Fe]],[Ve,[ze,qe]],[Ge,[He,Ze]],[$e,[Ye,We]],[Xe,[Qe,Je]],[oo,[eo,to]],[uo,[ro,no]],[so,[io,ao]],[co,[mo,fo]],[yo,[lo,po]],[To,[ko,bo]],[go,[xo,Po]],[Io,[Ko,So]]]);var en=class extends hn{#t;constructor(t){super(),this.#t=t}read(t){try{if(t.length<6)return!1;let o=t.readUInt8(5);if(o>2)return!1;let r=t.readUInt8(4);if(r>3)return!1;let a=t.subarray(6),f=t.readUInt16LE(2),m=tn.get(f);if(m){let[T,P]=m;this.emit(T,new No(Buffer.from(a),f,r,!!o,this.#t,P))}this.emit("*",a,f,r,!!o)}catch{return!1}}},No=class{#t;#o;#n;#r;#u;#a;constructor(t,o,r,a,f,m){this.#t=t,this.#o=o,this.#n=r,this.#r=a,this.#u=f,this.#a=m}#e;get parsed(){if(!this.#e)try{this.#e=this.#a(this.#u.decrypt(this.#t,this.#o,this.#n,this.#r))}catch(t){console.error(`[meter-core/pkt-stream] - ${t}`);return}return this.#e}};export{n as a,_o as b,R as c,L as d,M as e,z as f,H as g,Y as h,p as i,Hn as j,X as k,ot as l,ut as m,st as n,ct as o,u as p,nr as q,yt as r,Tt as s,gt as t,It as u,s as v,pr as w,l as x,dr as y,Dt as z,Bt as A,Ct as B,I as C,qo as D,N as E,Vo as F,jt as G,Ot as H,Vt as I,Gt as J,$t as K,Xt as L,oe as M,ue as N,se as O,ce as P,le as Q,ke as R,xe as S,Ke as T,_e as U,Yo as V,$r as W,De as X,Be as Y,Ce as Z,Qo as _,nu as $,je as aa,Ve as ba,Ge as ca,$e as da,Xe as ea,oo as fa,uo as ga,so as ha,co as ia,yo as ja,To as ka,go as la,Io as ma,tn as na,en as oa,No as pa};
