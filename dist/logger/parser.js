var L=Object.defineProperty;var te=Object.getOwnPropertyDescriptor;var se=Object.getOwnPropertyNames;var ie=Object.prototype.hasOwnProperty;var _e=(u,s,n)=>s in u?L(u,s,{enumerable:!0,configurable:!0,writable:!0,value:n}):u[s]=n;var re=(u,s)=>{for(var n in s)L(u,n,{get:s[n],enumerable:!0})},ue=(u,s,n,t)=>{if(s&&typeof s=="object"||typeof s=="function")for(let e of se(s))!ie.call(u,e)&&e!==n&&L(u,e,{get:()=>s[e],enumerable:!(t=te(s,e))||t.enumerable});return u};var de=u=>ue(L({},"__esModule",{value:!0}),u);var w=(u,s,n)=>(_e(u,typeof s!="symbol"?s+"":s,n),n),z=(u,s,n)=>{if(!s.has(u))throw TypeError("Cannot "+n)};var c=(u,s,n)=>(z(u,s,"read from private field"),n?n.call(u):s.get(u)),D=(u,s,n)=>{if(s.has(u))throw TypeError("Cannot add the same private member more than once");s instanceof WeakSet?s.add(u):s.set(u,n)},A=(u,s,n,t)=>(z(u,s,"write to private field"),t?t.call(u,n):s.set(u,n),n);var B=(u,s,n)=>(z(u,s,"access private method"),n);var fe={};re(fe,{Parser:()=>J});module.exports=de(fe);var ee=require("tiny-typed-emitter");var y=require("tiny-typed-emitter");function v(u){let s=Buffer.alloc(4);return s.writeUInt32LE(u),Math.round(s.readFloatLE()*100)/100}var m,C,b,M,Y,x,q,Z=class extends y.TypedEmitter{constructor(n,t,e=!0,a=!!process.env.DEV){super();D(this,M);D(this,x);w(this,"PartyStatusEffectRegistry");w(this,"LocalStatusEffectRegistry");D(this,m,void 0);D(this,C,void 0);D(this,b,void 0);w(this,"debug");w(this,"trace",!1);this.PartyStatusEffectRegistry=new Map,this.LocalStatusEffectRegistry=new Map,this.debug=a,A(this,m,n),A(this,C,t),A(this,b,e)}getStatusEffectRegistryForPlayer(n,t){let e=this.getPlayerRegistry(t),a=e.get(n);if(a)return a;let i=new Map;return e.set(n,i),i}hasStatusEffectRegistryForPlayer(n,t){return this.getPlayerRegistry(t).has(n)}getPlayerRegistry(n){switch(n){case 1:return this.LocalStatusEffectRegistry;case 0:return this.PartyStatusEffectRegistry;default:break}return this.LocalStatusEffectRegistry}RemoveLocalObject(n,t){let e=this.LocalStatusEffectRegistry.get(n);if(e)for(let[,a]of e)this.RemoveStatusEffect(n,a.instanceId,1,void 0,t);this.LocalStatusEffectRegistry.delete(n)}RemovePartyObject(n,t){let e=this.PartyStatusEffectRegistry.get(n);if(e)for(let[,a]of e)this.RemoveStatusEffect(n,a.instanceId,0,void 0,t);this.PartyStatusEffectRegistry.delete(n)}RegisterStatusEffect(n){let t=this.getStatusEffectRegistryForPlayer(n.targetId,n.type),e=t.get(n.instanceId);e?c(this,b)&&e.expirationTimer&&(clearTimeout(e.expirationTimer),e.expirationTimer=void 0):n.effectType===0&&this.emit("shieldApplied",n),t.set(n.instanceId,n),this.SetupStatusEffectTimeout(n)}HasAnyStatusEffect(n,t,e,a){if(!this.hasStatusEffectRegistryForPlayer(n,t))return!1;let i=this.getStatusEffectRegistryForPlayer(n,t);for(let[,_]of i)if(!(!c(this,b)&&!this.IsReplayStatusEffectValidElseRemove(_,a))){for(let r of e)if(r===_.statusEffectId)return!0}return!1}IsReplayStatusEffectValidElseRemove(n,t){return n.expireAt===void 0||n.expireAt.getTime()>t.getTime()?!0:(this.ExpireStatusEffectByTimeout(n),!1)}HasAnyStatusEffectFromParty(n,t,e,a,i){if(!this.hasStatusEffectRegistryForPlayer(n,t))return!1;let _=this.getStatusEffectRegistryForPlayer(n,t);for(let[,r]of _)if(!(!c(this,b)&&!this.IsReplayStatusEffectValidElseRemove(r,i))&&a.includes(r.statusEffectId)&&(this.ValidForWholeRaid(r)||c(this,m).getPartyIdFromEntityId(r.sourceId)===e))return!0;return!1}RemoveStatusEffect(n,t,e,a,i){if(!this.hasStatusEffectRegistryForPlayer(n,e))return;let _=this.getStatusEffectRegistryForPlayer(n,e),r=_.get(t);r&&(c(this,b)&&(clearTimeout(r.expirationTimer),r.expirationTimer=void 0),_.delete(t),a===4&&(c(this,b)||this.IsReplayStatusEffectValidElseRemove(r,i))&&this.RegisterValueUpdate(r,r.value,0))}GetStatusEffects(n,t,e){if(!this.hasStatusEffectRegistryForPlayer(n,t))return[];let a=this.getStatusEffectRegistryForPlayer(n,t);if(!c(this,b))for(let[,i]of a)this.IsReplayStatusEffectValidElseRemove(i,e);return[...a.values()]}GetStatusEffectsFromParty(n,t,e,a){if(!this.hasStatusEffectRegistryForPlayer(n,t))return[];let i=this.getStatusEffectRegistryForPlayer(n,t);if(!c(this,b))for(let[,_]of i)this.IsReplayStatusEffectValidElseRemove(_,a);return[...i.values()].filter(_=>this.ValidForWholeRaid(_)?!0:e===c(this,m).getPartyIdFromEntityId(_.sourceId))}Clear(n){let t=0;for(let[,a]of this.LocalStatusEffectRegistry){for(let[,i]of a)this.RemoveStatusEffect(i.targetId,i.instanceId,i.type,void 0,n);t+=a.size}let e=0;for(let[,a]of this.PartyStatusEffectRegistry){for(let[,i]of a)this.RemoveStatusEffect(i.targetId,i.instanceId,i.type,void 0,n);e+=a.size}this.trace&&console.log("On Clear SE in local",t,"in party",e),this.LocalStatusEffectRegistry.clear(),this.PartyStatusEffectRegistry.clear()}UpdateDuration(n,t,e,a){let _=this.getStatusEffectRegistryForPlayer(t,a).get(n);if(_){let r=e-_.timestamp;if(c(this,b)&&_.expirationTimer&&(this.trace&&console.log("Clearing timeout for",_.instanceId,"because of duration change"),clearTimeout(_.expirationTimer),_.expirationTimer=void 0),_.expireAt){let l=_.expireAt.getTime()+Number(r),o=l-_.pktTime.getTime();o>0?(this.trace&&console.log("Extending duration by",r,"ms","New timeout delay",o,"from",_.expireAt.toISOString(),"to",new Date(l).toISOString()),c(this,b)&&(_.expirationTimer=setTimeout(this.ExpireStatusEffectByTimeout.bind(this,_),o)),_.expireAt=new Date(l),_.timestamp=e):_.expireAt=void 0}}else this.debug&&console.error("Tried to update duration for SE with instanceId",n," on target",t,"but where is no such SE registered")}SyncStatusEffect(n,t,e,a,i){let _=B(this,x,q).call(this,t,i),r=_?0:1,l=_?t:e;if(!l)return;let d=this.getStatusEffectRegistryForPlayer(l,r).get(n);if(!d)return;let I=d.value;d.value=a,this.RegisterValueUpdate(d,I,a)}ValidForWholeRaid(n){return(n.buffCategory===3||n.buffCategory===1||n.buffCategory===2)&&n.category===1&&n.showType===1}SetupStatusEffectTimeout(n){if(n.expirationDelay>0&&n.expirationDelay<604800){let t=n.pktTime.getTime()>n.occurTime.getTime()?n.pktTime:n.occurTime,e=Math.ceil(n.expirationDelay*1e3),a=t.getTime()+e+Z.TIMEOUT_DELAY_MS-n.pktTime.getTime();n.expireAt=new Date(n.pktTime.getTime()+a),this.trace&&console.log("Setting up statuseffect expiration time for",n.name,n.instanceId,"to",n.expireAt.toISOString(),"with delay",a),c(this,b)&&(n.expirationTimer=setTimeout(this.ExpireStatusEffectByTimeout.bind(this,n),a))}}ExpireStatusEffectByTimeout(n){this.debug&&console.error("Triggered timeout on",n.name,"with iid",n.instanceId),this.RemoveStatusEffect(n.targetId,n.instanceId,n.type,void 0,new Date)}RegisterValueUpdate(n,t,e){n.effectType===0&&this.emit("shieldChanged",n,t,e)}newPC(n,t,e){let a=B(this,x,q).call(this,n.PCStruct.CharacterId,t);a?this.RemovePartyObject(n.PCStruct.CharacterId,e):this.RemoveLocalObject(n.PCStruct.PlayerId,e);for(let i of n.PCStruct.statusEffectDatas)this.RegisterStatusEffect(this.buildStatusEffect(i,a?n.PCStruct.CharacterId:n.PCStruct.PlayerId,i.SourceId,a?0:1,e))}buildStatusEffect(n,t,e,a,i){let _=n.Value?n.Value.readUInt32LE():0,r=n.Value?n.Value.readUInt32LE(8):0,l=_<r?_:r,o=0,d=0,I=0,P="Unknown",k=1,E=c(this,C).skillBuff.get(n.StatusEffectId);if(E){switch(P=E.name,E.category){case"debuff":o=1;break}switch(E.buffcategory){case"bracelet":d=1;break;case"etc":d=2;break;case"battleitem":d=3;break}switch(E.iconshowtype){case"all":I=1;break}switch(E.type){case"shield":k=0;break}}return{instanceId:n.EffectInstanceId,sourceId:e,statusEffectId:n.StatusEffectId,targetId:t,type:a,value:l,buffCategory:d,category:o,showType:I,expirationDelay:v(n.TotalTime),expirationTimer:void 0,timestamp:n.EndTick,expireAt:void 0,occurTime:n.OccurTime,name:P,pktTime:i,effectType:k}}getStatusEffects(n,t,e,a){let i=[],_=[],r=B(this,M,Y).call(this,n,e),l=this.GetStatusEffects(r?n.characterId:n.entityId,r?0:1,a);for(let o of l)_.push([o.statusEffectId,o.sourceId]);if(t){let o=B(this,M,Y).call(this,t,e),d=c(this,m).isEntityInParty(n.entityId),I=d?c(this,m).getPartyIdFromEntityId(n.entityId):void 0,P=d&&I?this.GetStatusEffectsFromParty(o?t.characterId:t.entityId,o?0:1,I,a):this.GetStatusEffects(o?t.characterId:t.entityId,o?0:1,a);for(let k of P)i.push([k.statusEffectId,k.sourceId])}return[_,i]}},N=Z;m=new WeakMap,C=new WeakMap,b=new WeakMap,M=new WeakSet,Y=function(n,t){if(n.entityType!==1)return!1;let e=n;return B(this,x,q).call(this,e.characterId,t)},x=new WeakSet,q=function(n,t){let e=c(this,m).isCharacterInParty(t),a=c(this,m).isCharacterInParty(n);if(e){if(!a||n===t)return!1;let i=c(this,m).getPartyIdFromCharacterId(t),_=c(this,m).getPartyIdFromCharacterId(n);return i===_}return!1},w(N,"TIMEOUT_DELAY_MS",1e3);var j=class{#e;#s;#i;#r;entities=new Map;localPlayer;constructor(s,n,t,e){this.#e=s,this.#s=n,this.#i=t,this.#r=e,this.localPlayer={entityId:0n,entityType:1,name:"You",class:0,gearLevel:0,characterId:0n}}processNewPC(s){let n=s.parsed;if(!n)return;let t={entityId:n.PCStruct.PlayerId,entityType:1,name:n.PCStruct.Name,class:n.PCStruct.ClassId,gearLevel:v(n.PCStruct.GearLevel),characterId:n.PCStruct.CharacterId};this.entities.set(t.entityId,t);let e=this.#e.getEntityId(t.characterId);return e&&this.#s.changeEntityId(e,n.PCStruct.PlayerId),this.#e.addMapping(t.characterId,t.entityId),this.#s.completeEntry(t.characterId,t.entityId),this.#i.newPC(n,this.localPlayer.characterId,s.time),t}processInitEnv(s){let n=s.parsed;if(!n)return;this.localPlayer.entityId!==0n&&this.#s.changeEntityId(this.localPlayer.entityId,n.PlayerId),this.entities.clear();let t={entityId:n.PlayerId,entityType:1,name:this.localPlayer.name,class:this.localPlayer.class,gearLevel:this.localPlayer.gearLevel,characterId:this.localPlayer.characterId};this.localPlayer=t,this.entities.set(t.entityId,t),this.#e.clear(),this.#i.Clear(s.time),t.characterId!==0n&&this.#e.addMapping(t.characterId,t.entityId),this.localPlayer&&this.localPlayer.characterId&&this.localPlayer.characterId>0n&&this.#s.completeEntry(this.localPlayer.characterId,n.PlayerId)}processInitPC(s){let n=s.parsed;if(!n)return;this.entities.clear();let t={entityId:n.PlayerId,entityType:1,name:n.Name,class:n.ClassId,gearLevel:v(n.GearLevel),characterId:n.CharacterId};this.localPlayer=t,this.entities.set(t.entityId,t),this.#e.addMapping(t.characterId,t.entityId),this.#s.setOwnName(n.Name),this.#s.completeEntry(t.characterId,n.PlayerId),this.#i.RemoveLocalObject(n.PlayerId,s.time);for(let e of n.statusEffectDatas){let a=this.getSourceEntity(e.SourceId);this.#i.RegisterStatusEffect(this.#i.buildStatusEffect(e,n.PlayerId,a.entityId,1,s.time))}return t}processNewNpc(s){let n=s.parsed;if(!n)return;let t=!1,e=this.#r.npc.get(n.NpcStruct.TypeId);e&&["boss","raid","epic_raid","commander"].includes(e.grade)&&(t=!0);let a={entityId:n.NpcStruct.ObjectId,entityType:2,name:e?.name??n.NpcStruct.ObjectId.toString(16),typeId:n.NpcStruct.TypeId,isBoss:t},i=this.#r.getNpcEsther(n.NpcStruct.TypeId);i!==void 0&&(a.entityType=4,a.name=i.name,a.icon=i.icon),this.entities.set(a.entityId,a),this.#i.RemoveLocalObject(n.NpcStruct.ObjectId,s.time);for(let _ of n.NpcStruct.statusEffectDatas){let r=this.getSourceEntity(_.SourceId);this.#i.RegisterStatusEffect(this.#i.buildStatusEffect(_,n.NpcStruct.ObjectId,r.entityId,1,s.time))}return a}processNewNpcSummon(s){let n=s.parsed;if(!n)return;let t=!1,e=this.#r.npc.get(n.NpcData.TypeId);e&&["boss","raid","epic_raid","commander"].includes(e.grade)&&(t=!0);let a={entityId:n.NpcData.ObjectId,entityType:3,name:e?.name??n.NpcData.ObjectId.toString(16),ownerId:n.OwnerId,typeId:n.NpcData.TypeId,isBoss:t};this.#i.RemoveLocalObject(n.NpcData.ObjectId,s.time);for(let i of n.NpcData.statusEffectDatas){let _=this.getSourceEntity(i.SourceId);this.#i.RegisterStatusEffect(this.#i.buildStatusEffect(i,n.NpcData.ObjectId,_.entityId,1,s.time))}return this.entities.set(a.entityId,a),a}getSourceEntity(s){let n=this.entities.get(s);if((n?.entityType===5||n?.entityType===3)&&(s=n.ownerId),n=this.entities.get(s),n)return n;let t={entityId:s,entityType:2,name:s.toString(16)};return this.entities.set(s,t),t}guessIsPlayer(s,n){let t=this.#r.getSkillClassId(n);if(t!==0){let e;if(s.entityType===1){let a=s;if(a.class===t)return a;e={entityId:a.entityId,entityType:1,name:a.name,class:t,gearLevel:a.gearLevel,characterId:a.characterId}}else e={entityId:s.entityId,entityType:1,name:s.name,class:t,gearLevel:0,characterId:0n};return this.entities.set(s.entityId,e),e}return s}getOrCreateEntity(s){let n=this.entities.get(s);return n||(n={entityId:s,entityType:0,name:s.toString(16)},this.entities.set(s,n)),n}};var g=require("tiny-typed-emitter");var oe={isLive:!0,dontResetOnZoneChange:!1,resetAfterPhaseTransition:!1,splitOnPhaseTransition:!1},H=class extends g.TypedEmitter{#e;encounters;#s;#i;#r;#a;options;resetTimer;phaseTransitionResetRequest;phaseTransitionResetRequestTime;constructor(s,n,t,e,a){super(),this.#s=s,this.#i=n,this.#r=t,this.#a=e,this.options={...oe,...a},this.resetTimer=null,this.phaseTransitionResetRequest=!1,this.phaseTransitionResetRequestTime=0,this.encounters=[],this.#e={startedOn:0,lastCombatPacket:0,fightStartedOn:0,localPlayer:this.#s.localPlayer.name,currentBoss:void 0,entities:new Map,damageStatistics:{totalDamageDealt:0,topDamageDealt:0,totalDamageTaken:0,topDamageTaken:0,totalHealingDone:0,topHealingDone:0,totalShieldDone:0,topShieldDone:0,debuffs:new Map,buffs:new Map,topShieldGotten:0,totalEffectiveShieldingDone:0,topEffectiveShieldingDone:0,topEffectiveShieldingUsed:0,effectiveShieldingBuffs:new Map,appliedShieldingBuffs:new Map}}}onCounterAttack(s,n){let t=this.updateEntity(s,{},n);t.hits.counter+=1}onInitEnv(s,n){this.options.isLive?(this.#e.entities.forEach((t,e,a)=>{t.hits.total===0&&a.delete(e)}),this.options.dontResetOnZoneChange===!1&&this.resetTimer===null&&(this.resetTimer=setTimeout(()=>{this.resetState(+n+6e3)},6e3),this.emit("message","new-zone"))):(this.splitEncounter(n),this.emit("message","new-zone"))}splitEncounter(s){if(this.#e.fightStartedOn!==0&&(this.#e.damageStatistics.totalDamageDealt!==0||this.#e.damageStatistics.totalDamageTaken!==0)){let n=structuredClone(this.#e);this.applyBreakdowns(n.entities),this.encounters.push(n)}this.resetState(+s)}getBossIfStillExist(){if(this.#e.currentBoss?.id){let s=BigInt(`0x0${this.#e.currentBoss?.id}`);return this.#s.entities.has(s)?this.#e.currentBoss:void 0}}resetState(s){this.cancelReset(),this.#r.reset(),this.#e={startedOn:+s,lastCombatPacket:+s,fightStartedOn:0,localPlayer:this.#s.localPlayer.name,currentBoss:this.getBossIfStillExist(),entities:new Map,damageStatistics:{totalDamageDealt:0,topDamageDealt:0,totalDamageTaken:0,topDamageTaken:0,totalHealingDone:0,topHealingDone:0,totalShieldDone:0,topShieldDone:0,debuffs:new Map,buffs:new Map,appliedShieldingBuffs:new Map,effectiveShieldingBuffs:new Map,topEffectiveShieldingDone:0,topEffectiveShieldingUsed:0,topShieldGotten:0,totalEffectiveShieldingDone:0}},this.emit("reset-state",this.#e)}cancelReset(){this.resetTimer&&clearTimeout(this.resetTimer),this.resetTimer=null}onPhaseTransition(s,n){this.options.isLive&&(this.emit("message",`phase-transition-${s}`),this.options.resetAfterPhaseTransition&&(this.phaseTransitionResetRequest=!0,this.phaseTransitionResetRequestTime=+n)),!this.options.isLive&&this.options.splitOnPhaseTransition&&this.splitEncounter(n)}updateOptions(s){this.options={...this.options,...s}}onDeath(s,n){let t=this.#e.entities.get(s.name),e=0;t?t.isDead?e=t.deaths:e=t.deaths+1:e=1,this.updateEntity(s,{isDead:!0,deathTime:+n,deaths:e},n)}onDamage(s,n,t,e,a){if((e.modifier&15)===11&&e.skillId===0&&e.skillEffectId===0)return;this.phaseTransitionResetRequest&&this.phaseTransitionResetRequestTime>0&&this.phaseTransitionResetRequestTime<+a-8e3&&(this.resetState(+a),this.phaseTransitionResetRequest=!1);let[i,_]=this.#i.getStatusEffects(s,t,this.#s.localPlayer.characterId,a);if(this.#a.isBattleItem(e.skillEffectId,"attack")&&n&&n.entityType===5){let p=n;e.skillEffectId=p.skillEffectId}let r=this.updateEntity(s,{},a),l=this.updateEntity(t,{currentHp:e.targetCurHp,maxHp:e.targetMaxHp},a);if(!r||!l)return;!l.isPlayer&&e.targetCurHp<0&&(e.damage=e.damage+e.targetCurHp);let o=e.skillId;e.skillId===0&&e.skillEffectId!==0&&(o=e.skillEffectId);let d=r.skills.get(o);d||(d={...this.createEntitySkill(),id:o,...this.getSkillNameIcon(e.skillId,e.skillEffectId)},r.skills.set(o,d));let I=e.modifier&15,P=(e.modifier>>4&7)-1,k=(I&9)!==0,E=new Set,R=new Set;i.forEach(p=>{E.add(p[0])}),_.forEach(p=>{R.add(p[0])}),d.damageDealt+=e.damage,e.damage>d.maxDamage&&(d.maxDamage=e.damage),r.hits.total+=1,d.hits.total+=1,r.damageDealt+=e.damage,l.damageTaken+=e.damage;let $=k?1:0;r.hits.crit+=$,d.hits.crit+=$;let F=!1,W=!1,O=this.#a.getSkillEffectDirectionalMask(e.skillEffectId)-1;if(O===0||O===2){W=P===0;let p=W?1:0;r.hits.backAttack+=p,r.hits.totalBackAttack+=1,d.hits.backAttack+=p,d.hits.totalBackAttack+=1}if(O===1||O===2){F=P===1;let p=F?1:0;r.hits.frontAttack+=p,r.hits.totalFrontAttack+=1,d.hits.frontAttack+=p,d.hits.totalFrontAttack+=1}if(r.isPlayer){this.#e.damageStatistics.totalDamageDealt+=e.damage,this.#e.damageStatistics.topDamageDealt=Math.max(this.#e.damageStatistics.topDamageDealt,r.damageDealt);let p=!1,T=!1;E.forEach(f=>{if(!this.#e.damageStatistics.buffs.has(f)){let S=this.#a.getStatusEffectHeaderData(f);S&&this.#e.damageStatistics.buffs.set(f,S)}let h=this.#e.damageStatistics.buffs.get(f);h&&!p&&(p=(h.buffcategory==="classskill"||h.buffcategory==="identity"||h.buffcategory==="ability")&&h.source.skill!==void 0&&h.target===1&&this.#a.isSupportClassId(h.source.skill.classid))}),R.forEach(f=>{if(!this.#e.damageStatistics.debuffs.has(f)){let S=this.#a.getStatusEffectHeaderData(f);S&&this.#e.damageStatistics.debuffs.set(f,S)}let h=this.#e.damageStatistics.debuffs.get(f);h&&!T&&(T=(h.buffcategory==="classskill"||h.buffcategory==="identity"||h.buffcategory==="ability")&&h.source.skill!==void 0&&h.target===1&&this.#a.isSupportClassId(h.source.skill.classid))});let Q=T?1:0,X=p?1:0;d.damageDealtBuffedBySupport+=p?e.damage:0,d.damageDealtDebuffedBySupport+=T?e.damage:0,E.forEach(f=>{let h=d.damageDealtBuffedBy.get(f)??0;d.damageDealtBuffedBy.set(f,h+e.damage);let S=r.damageDealtBuffedBy.get(f)??0;r.damageDealtBuffedBy.set(f,S+e.damage)}),R.forEach(f=>{let h=d.damageDealtDebuffedBy.get(f)??0;d.damageDealtDebuffedBy.set(f,h+e.damage);let S=r.damageDealtDebuffedBy.get(f)??0;r.damageDealtDebuffedBy.set(f,S+e.damage)}),r.damageDealtBuffedBySupport+=p?e.damage:0,r.damageDealtDebuffedBySupport+=T?e.damage:0,r.hits.hitsBuffedBySupport+=X,r.hits.hitsDebuffedBySupport+=Q,E.forEach(f=>{let h=r.hits.hitsBuffedBy.get(f)??0;r.hits.hitsBuffedBy.set(f,h+1);let S=d.hits.hitsBuffedBy.get(f)??0;d.hits.hitsBuffedBy.set(f,S+1)}),R.forEach(f=>{let h=r.hits.hitsDebuffedBy.get(f)??0;r.hits.hitsDebuffedBy.set(f,h+1);let S=d.hits.hitsDebuffedBy.get(f)??0;d.hits.hitsDebuffedBy.set(f,S+1)}),d.hits.hitsBuffedBySupport+=X,d.hits.hitsDebuffedBySupport+=Q;let ne={timestamp:+a,damage:e.damage,targetEntity:l.id,isCrit:k,isBackAttack:W,isFrontAttack:F,isBuffedBySupport:p,isDebuffedBySupport:T,buffedBy:[...E],debuffedBy:[...R]},ae=BigInt("0x"+r.id);this.#r.addBreakdown(ae,o,ne)}l.isPlayer&&(this.#e.damageStatistics.totalDamageTaken+=e.damage,this.#e.damageStatistics.topDamageTaken=Math.max(this.#e.damageStatistics.topDamageTaken,l.damageTaken)),l.isBoss&&(this.#e.currentBoss=l),this.#e.fightStartedOn===0&&(this.#e.fightStartedOn=+a),this.#e.lastCombatPacket=+a}onStartSkill(s,n,t){let e=this.updateEntity(s,{isDead:!1},t);if(e){e.hits.casts+=1;let a=e.skills.get(n);a||(a={...this.createEntitySkill(),id:n,...this.getSkillNameIcon(n,0)},e.skills.set(n,a)),a.hits.casts+=1}}onShieldUsed(s,n,t,e){if(e<0&&console.error("Shield change values was negative, shield ammount increased"),s.entityType===1&&n.entityType===1){if(!this.#e.damageStatistics.effectiveShieldingBuffs.has(t)){let o=this.#a.getStatusEffectHeaderData(t);o&&this.#e.damageStatistics.effectiveShieldingBuffs.set(t,o)}let a=new Date,i=this.updateEntity(s,{},a),_=this.updateEntity(n,{},a);i.damagePreventedByShield+=e;let r=i.damagePreventedByShieldBy.get(t)??0;i.damagePreventedByShieldBy.set(t,r+e),this.#e.damageStatistics.topEffectiveShieldingUsed=Math.max(i.damagePreventedByShield,this.#e.damageStatistics.topEffectiveShieldingUsed),_.damagePreventedWithShieldOnOthers+=e;let l=_.damagePreventedWithShieldOnOthersBy.get(t)??0;_.damagePreventedWithShieldOnOthersBy.set(t,l+e),this.#e.damageStatistics.topEffectiveShieldingDone=Math.max(_.damagePreventedWithShieldOnOthers,this.#e.damageStatistics.topEffectiveShieldingDone),this.#e.damageStatistics.totalEffectiveShieldingDone+=e}}onShieldApplied(s,n,t,e){let a=new Date,i=this.updateEntity(s,{},a),_=this.updateEntity(n,{},a);if(_.isPlayer&&i.isPlayer){if(!this.#e.damageStatistics.appliedShieldingBuffs.has(t)){let o=this.#a.getStatusEffectHeaderData(t);o&&this.#e.damageStatistics.appliedShieldingBuffs.set(t,o)}i.shieldReceived+=e,_.shieldDone+=e;let r=_.shieldDoneBy.get(t)??0;_.shieldDoneBy.set(t,r+e);let l=i.shieldReceivedBy.get(t)??0;i.shieldReceivedBy.set(t,l+e),this.#e.damageStatistics.topShieldDone=Math.max(_.shieldDone,this.#e.damageStatistics.topShieldDone),this.#e.damageStatistics.topShieldGotten=Math.max(i.shieldReceived,this.#e.damageStatistics.topShieldGotten),this.#e.damageStatistics.totalShieldDone+=e}}getSkillNameIcon(s,n){if(s===0&&n===0)return{name:"Bleed",icon:"buff_168.png"};if(s===0){let t=this.#a.skillEffect.get(n);if(t&&t.itemname)return{name:t.itemname,icon:t.icon??""};if(t){if(t.sourceskill){let e=this.#a.skill.get(t.sourceskill);if(e)return{name:e.name,icon:e.icon}}else{let e=this.#a.skill.get(Math.floor(n/10));if(e)return{name:e.name,icon:e.icon}}return{name:t.comment}}else return{name:this.#a.getSkillName(s)}}else{let t=this.#a.skill.get(s);return!t&&(t=this.#a.skill.get(s-s%10),!t)?{name:this.#a.getSkillName(s),icon:""}:t.summonsourceskill?(t=this.#a.skill.get(t.summonsourceskill),t?{name:t.name+" (Summon)",icon:t.icon}:{name:this.#a.getSkillName(s),icon:""}):t.sourceskill?(t=this.#a.skill.get(t.sourceskill),t?{name:t.name,icon:t.icon}:{name:this.#a.getSkillName(s),icon:""}):{name:t.name,icon:t.icon}}}updateEntity(s,n,t){let e={lastUpdate:+t},a=this.#e.entities.get(s.name),i={};if(!a||s.entityType===1&&a.isPlayer!==!0){if(s.entityType===1){let _=s;i={classId:_.class,gearScore:_.gearLevel,isPlayer:!0}}else if(s.entityType===2||s.entityType===3){let _=s;i={npcId:_.typeId,isBoss:_.isBoss}}else if(s.entityType===4){let _=s;i={npcId:_.typeId,isBoss:_.isBoss,isEsther:!0,icon:_.icon}}}return a?Object.assign(a,n,e,i):(a={...this.createEntity(),...n,...e,...i,name:s.name,id:s.entityId.toString(16)},this.#e.entities.set(s.name,a)),a}updateOrCreateEntity(s,n,t){if(!(!n.name||!n.id)){for(let[e,a]of this.#e.entities)if(n.id===a.id){this.#e.entities.delete(e),this.updateEntity(s,{...a,...n},t);return}this.updateEntity(s,n,t)}}createEntitySkill(){return{id:0,name:"",icon:"",damageDealt:0,damageDealtDebuffedBySupport:0,damageDealtBuffedBySupport:0,maxDamage:0,hits:{casts:0,total:0,crit:0,backAttack:0,totalBackAttack:0,frontAttack:0,totalFrontAttack:0,counter:0,hitsDebuffedBySupport:0,hitsBuffedBySupport:0,hitsBuffedBy:new Map,hitsDebuffedBy:new Map},breakdown:[],damageDealtDebuffedBy:new Map,damageDealtBuffedBy:new Map}}createEntity(){return{lastUpdate:0,id:"",npcId:0,name:"",classId:0,isBoss:!1,isPlayer:!1,isDead:!1,deaths:0,deathTime:0,gearScore:0,currentHp:0,maxHp:0,damageDealt:0,damageDealtDebuffedBySupport:0,damageDealtBuffedBySupport:0,healingDone:0,shieldDone:0,damageTaken:0,skills:new Map,hits:{casts:0,total:0,crit:0,backAttack:0,totalBackAttack:0,frontAttack:0,totalFrontAttack:0,counter:0,hitsDebuffedBySupport:0,hitsBuffedBySupport:0,hitsBuffedBy:new Map,hitsDebuffedBy:new Map},damageDealtDebuffedBy:new Map,damageDealtBuffedBy:new Map,damagePreventedByShieldBy:new Map,damagePreventedWithShieldOnOthersBy:new Map,shieldDoneBy:new Map,shieldReceivedBy:new Map,damagePreventedWithShieldOnOthers:0,damagePreventedByShield:0,shieldReceived:0}}getBroadcast(){let s={...this.#e};return s.entities=new Map,this.#e.entities.forEach((n,t)=>{!n.isPlayer&&!n.isEsther||s.entities.set(t,{...n})}),s.localPlayer=this.#s.localPlayer.name,s}applyBreakdowns(s){s.forEach(n=>{n.skills.forEach(t=>{let e=BigInt("0x"+n.id),a=this.#r.getBreakdowns(e,t.id);a&&(t.breakdown=[...a])})}),this.#r.reset()}};var G=class{characterIdToPartyId;entityIdToPartyId;raidInstanceToPartyInstances;ownName;characterNameToCharacterId;#e;constructor(s){this.characterIdToPartyId=new Map,this.entityIdToPartyId=new Map,this.raidInstanceToPartyInstances=new Map,this.characterNameToCharacterId=new Map,this.#e=s}add(s,n,t=void 0,e=void 0,a=void 0){!t&&!e||(t&&!e&&(e=this.#e.getEntityId(t)),e&&!t&&(t=this.#e.getEntityId(e)),t&&this.characterIdToPartyId.set(t,n),e&&this.entityIdToPartyId.set(e,n),a&&t&&this.characterNameToCharacterId.set(a,t),this.registerPartyId(s,n))}completeEntry(s,n){let t=this.getPartyIdFromCharacterId(s),e=this.getPartyIdFromEntityId(n);t&&e||(!t&&e&&this.characterIdToPartyId.set(s,e),!e&&t&&this.entityIdToPartyId.set(n,t))}changeEntityId(s,n){let t=this.getPartyIdFromEntityId(s);t&&(this.entityIdToPartyId.delete(s),this.entityIdToPartyId.set(n,t))}setOwnName(s){this.ownName=s}remove(s,n){if(n===this.ownName){this.removePartyMappings(s);return}let t=this.characterNameToCharacterId.get(n);if(this.characterNameToCharacterId.delete(n),!t)return;this.characterIdToPartyId.delete(t);let e=this.#e.getEntityId(t);e&&this.characterIdToPartyId.delete(e)}isCharacterInParty(s){return this.characterIdToPartyId.has(s)}isEntityInParty(s){return this.entityIdToPartyId.has(s)}getPartyIdFromCharacterId(s){return this.characterIdToPartyId.get(s)}getPartyIdFromEntityId(s){return this.entityIdToPartyId.get(s)}removePartyMappings(s){let n=this.getRaidInstanceId(s),t=n?this.raidInstanceToPartyInstances.get(n)??new Set([s]):new Set([s]);for(let[e,a]of this.characterIdToPartyId)if(t.has(a)){this.characterIdToPartyId.delete(e);for(let[i,_]of this.characterNameToCharacterId)if(e===_){this.characterNameToCharacterId.delete(i);break}}for(let[e,a]of this.entityIdToPartyId)t.has(a)&&this.entityIdToPartyId.delete(e)}getRaidInstanceId(s){for(let n of this.raidInstanceToPartyInstances)if(n[1].has(s))return n[0]}registerPartyId(s,n){let t=this.raidInstanceToPartyInstances.get(s);t||(t=new Set,this.raidInstanceToPartyInstances.set(s,t)),t.add(n)}partyInfo(s,n,t){let e=s.parsed;if(e){if(e.MemberDatas.length===1&&e.MemberDatas[0]?.Name===t.name){this.remove(e.PartyInstanceId,e.MemberDatas[0].Name);return}this.removePartyMappings(e.PartyInstanceId);for(let a of e.MemberDatas){a.CharacterId===t.characterId&&this.setOwnName(a.Name);let i=this.#e.getEntityId(a.CharacterId);if(i){let _=n.get(i);if(_&&_.entityType===1&&_.name!==a.Name){let r=_;r.gearLevel=v(a.GearLevel),r.name=a.Name,r.class=a.ClassId}}this.add(e.RaidInstanceId,e.PartyInstanceId,a.CharacterId,i,a.Name)}}}};var V=class{entityToCharacterId;characterToEntityId;constructor(){this.entityToCharacterId=new Map,this.characterToEntityId=new Map}addMapping(s,n){this.entityToCharacterId.set(n,s),this.characterToEntityId.set(s,n)}getCharacterId(s){return this.entityToCharacterId.get(s)}getEntityId(s){return this.characterToEntityId.get(s)}clear(){this.entityToCharacterId.clear(),this.characterToEntityId.clear()}};var U=class{entityToSkillBreakdown;constructor(){this.entityToSkillBreakdown=new Map}reset(){this.entityToSkillBreakdown.clear()}addOrGetEntity(s){return this.entityToSkillBreakdown.has(s)||this.entityToSkillBreakdown.set(s,new Map),this.entityToSkillBreakdown.get(s)}removeEntry(s){this.entityToSkillBreakdown.delete(s)}addBreakdown(s,n,t){let e=this.addOrGetEntity(s);if(e.has(n))e.get(n).push(t);else{let a=new Array(t);e.set(n,a)}}getBreakdowns(s,n){let t=this.entityToSkillBreakdown.get(s);if(t)return t.get(n)}clearBreakdowns(s,n){let t=this.entityToSkillBreakdown.get(s);t&&t.delete(n)}};var J=class extends ee.TypedEmitter{#e;#s;#i;#r;#a;#_;#n;#t;#u;#d;constructor(s,n,t){super(),this.#e=s,this.#s=n,this.#i=new V,this.#r=new U,this.#a=new G(this.#i),this.#_=new N(this.#a,this.#s,t.isLive??!0),this.#n=new j(this.#i,this.#a,this.#_,this.#s),this.#t=new H(this.#n,this.#_,this.#r,this.#s,t),this.#t.emit=this.emit.bind(this),this.#u=!1,this.#d=!1,this.#t.options.isLive&&setInterval(this.broadcastStateChange.bind(this),100),this.#e.on("AbilityChangeNotify",e=>{}).on("ActiveAbilityNotify",e=>{}).on("AddonSkillFeatureChangeNotify",e=>{}).on("BlockSkillStateNotify",e=>{}).on("CounterAttackNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.entities.get(a.SourceId);i&&this.#t.onCounterAttack(i,e.time)}).on("DeathNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.entities.get(a.TargetId);i&&this.#t.onDeath(i,e.time)}).on("IdentityGaugeChangeNotify",e=>{}).on("InitAbility",e=>{}).on("InitEnv",e=>{this.#n.processInitEnv(e),this.#t.onInitEnv(e,e.time)}).on("InitLocal",e=>{}).on("InitPC",e=>{let a=this.#n.processInitPC(e);if(a&&e.parsed){let i=this.#s.getStatPairMap(e.parsed.statPair);this.#t.updateOrCreateEntity(a,{id:a.entityId.toString(16),name:a.name,classId:a.class,isPlayer:!0,gearScore:a.gearLevel,currentHp:Number(i.get(1))||0,maxHp:Number(i.get(27))||0},e.time)}}).on("MigrationExecute",e=>{if(this.#n.localPlayer.characterId!==0n)return;let a=e.parsed;a&&(this.#n.localPlayer.characterId=a.Account_CharacterId1<a.Account_CharacterId2?a.Account_CharacterId1:a.Account_CharacterId2)}).on("NewNpc",e=>{let a=this.#n.processNewNpc(e);if(a&&e.parsed){let i=this.#s.getStatPairMap(e.parsed.NpcStruct.statPair);this.#t.updateOrCreateEntity(a,{id:a.entityId.toString(16),name:a.name,npcId:a.typeId,isPlayer:!1,isBoss:a.isBoss,currentHp:Number(i.get(1))||0,maxHp:Number(i.get(27))||0},e.time)}}).on("NewNpcSummon",e=>{let a=this.#n.processNewNpcSummon(e);if(a&&e.parsed){let i=this.#s.getStatPairMap(e.parsed.NpcData.statPair);this.#t.updateOrCreateEntity(a,{id:a.entityId.toString(16),name:a.name,npcId:a.typeId,isPlayer:!1,isBoss:a.isBoss,currentHp:Number(i.get(1))||0,maxHp:Number(i.get(27))||0},e.time)}}).on("NewPC",e=>{let a=this.#n.processNewPC(e);if(a&&e.parsed){let i=this.#s.getStatPairMap(e.parsed.PCStruct.statPair);this.#t.updateOrCreateEntity(a,{id:a.entityId.toString(16),name:a.name,classId:a.class,isPlayer:!0,gearScore:a.gearLevel,currentHp:Number(i.get(1))||0,maxHp:Number(i.get(27))||0},e.time)}}).on("NewProjectile",e=>{let a=e.parsed;if(!a)return;let i={entityId:a.projectileInfo.ProjectileId,entityType:5,name:a.projectileInfo.ProjectileId.toString(16),ownerId:a.projectileInfo.OwnerId,skillEffectId:a.projectileInfo.SkillEffect,skillId:a.projectileInfo.SkillId};this.#n.entities.set(i.entityId,i)}).on("ParalyzationStateNotify",e=>{}).on("PartyInfo",e=>{this.#a.partyInfo(e,this.#n.entities,this.#n.localPlayer)}).on("PartyLeaveResult",e=>{let a=e.parsed;a&&this.#a.remove(a.PartyInstanceId,a.Name)}).on("PartyPassiveStatusEffectAddNotify",e=>{}).on("PartyPassiveStatusEffectRemoveNotify",e=>{}).on("PartyStatusEffectAddNotify",e=>{let a=e.parsed;if(a)for(let i of a.statusEffectDatas){let _=a.PlayerIdOnRefresh!==0n?a.PlayerIdOnRefresh:i.SourceId,r=this.#n.getSourceEntity(_);this.#_.RegisterStatusEffect(this.#_.buildStatusEffect(i,a.CharacterId,r.entityId,0,e.time))}}).on("PartyStatusEffectRemoveNotify",e=>{let a=e.parsed;if(a)for(let i of a.statusEffectIds)this.#_.RemoveStatusEffect(a.CharacterId,i,0,a.Reason,e.time)}).on("PartyStatusEffectResultNotify",e=>{let a=e.parsed;a&&this.#a.add(a.RaidInstanceId,a.PartyInstanceId,a.CharacterId)}).on("PassiveStatusEffectAddNotify",e=>{}).on("PassiveStatusEffectRemoveNotify",e=>{}).on("RaidBossKillNotify",e=>{this.#t.onPhaseTransition(1,e.time)}).on("RaidResult",e=>{this.#t.onPhaseTransition(0,e.time)}).on("RemoveObject",e=>{let a=e.parsed;if(a)for(let i of a.unpublishedObjects)this.#_.RemoveLocalObject(i.ObjectId,e.time)}).on("SkillDamageAbnormalMoveNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.getSourceEntity(a.SourceId);a.SkillDamageAbnormalMoveEvents.forEach(_=>{let r=this.#n.getOrCreateEntity(_.skillDamageEvent.TargetId),l=this.#n.getOrCreateEntity(a.SourceId);this.#t.onDamage(i,l,r,{skillId:a.SkillId,skillEffectId:a.SkillEffectId,damage:Number(_.skillDamageEvent.Damage),modifier:_.skillDamageEvent.Modifier,targetCurHp:Number(_.skillDamageEvent.CurHp),targetMaxHp:Number(_.skillDamageEvent.MaxHp)},e.time)})}).on("SkillDamageNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.getSourceEntity(a.SourceId);a.SkillDamageEvents.forEach(_=>{let r=this.#n.getOrCreateEntity(_.TargetId),l=this.#n.getOrCreateEntity(a.SourceId);this.#t.onDamage(i,l,r,{skillId:a.SkillId,skillEffectId:a.SkillEffectId,damage:Number(_.Damage),modifier:_.Modifier,targetCurHp:Number(_.CurHp),targetMaxHp:Number(_.MaxHp)},e.time)})}).on("SkillStageNotify",e=>{}).on("SkillStartNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.getSourceEntity(a.SourceId);i=this.#n.guessIsPlayer(i,a.SkillId),this.#t.onStartSkill(i,a.SkillId,e.time)}).on("StatusEffectAddNotify",e=>{let a=e.parsed;if(!a)return;let i=this.#n.getSourceEntity(a.statusEffectData.SourceId);this.#_.RegisterStatusEffect(this.#_.buildStatusEffect(a.statusEffectData,a.ObjectId,i.entityId,1,e.time))}).on("StatusEffectDurationNotify",e=>{let a=e.parsed;a&&this.#_.UpdateDuration(a.EffectInstanceId,a.TargetId,a.ExpirationTick,1)}).on("StatusEffectRemoveNotify",e=>{let a=e.parsed;if(a)for(let i of a.statusEffectIds)this.#_.RemoveStatusEffect(a.ObjectId,i,1,a.Reason,e.time)}).on("StatusEffectSyncDataNotify",e=>{}).on("TriggerBossBattleStatus",e=>{this.#t.onPhaseTransition(2,e.time)}).on("TriggerFinishNotify",e=>{}).on("TriggerStartNotify",e=>{let a=e.parsed;if(a)switch(a.TriggerSignalType){case 57:case 59:case 61:case 63:case 74:case 76:this.#d=!0,this.#u=!1;break;case 58:case 60:case 62:case 64:case 75:case 77:this.#d=!1,this.#u=!0;break}}).on("TroopMemberUpdateMinNotify",e=>{}).on("ZoneObjectUnpublishNotify",e=>{let a=e.parsed;a&&this.#_.RemoveLocalObject(a.ObjectId,e.time)}).on("ZoneStatusEffectAddNotify",e=>{}).on("StatusEffectSyncDataNotify",e=>{let a=e.parsed;a&&this.#_.SyncStatusEffect(a.EffectInstanceId,a.CharacterId,a.ObjectId,a.Value,this.#n.localPlayer.characterId)}).on("TroopMemberUpdateMinNotify",e=>{let a=e.parsed;if(a&&a.statusEffectDatas.length>0)for(let i of a.statusEffectDatas){let _=this.#i.getEntityId(a.CharacterId),r=i.Value?i.Value.readUInt32LE():0,l=i.Value?i.Value.readUInt32LE(8):0,o=r<l?r:l;this.#_.SyncStatusEffect(i.EffectInstanceId,a.CharacterId,_,o,this.#n.localPlayer.characterId)}}).on("ZoneStatusEffectRemoveNotify",e=>{}),this.#_.on("shieldApplied",e=>{let a=e.targetId;if(e.type===0&&(a=this.#i.getEntityId(e.targetId)??a),a===void 0)return;let i=this.#n.getSourceEntity(e.sourceId),_=this.#n.getOrCreateEntity(a);this.#t.onShieldApplied(_,i,e.statusEffectId,e.value)}).on("shieldChanged",(e,a,i)=>{let _=e.targetId;if(e.type===0&&(_=this.#i.getEntityId(e.targetId)??_),_===void 0)return;let r=this.#n.getSourceEntity(e.sourceId),l=this.#n.getOrCreateEntity(_);this.#t.onShieldUsed(l,r,e.statusEffectId,a-i)})}broadcastStateChange(){this.emit("state-change",this.#t.getBroadcast())}reset(){this.#t.resetState(+new Date)}cancelReset(){this.#t.cancelReset()}updateOptions(s){this.#t.updateOptions(s)}get encounters(){return this.#t.splitEncounter(new Date),this.#t.encounters}};0&&(module.exports={Parser});
