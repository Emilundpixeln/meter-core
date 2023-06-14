import{a as Q,b as X}from"../chunk-2WLTHR4C.mjs";import"../chunk-NYUBB7L6.mjs";import{a as N,b as V,g as Z,h as z,i as A}from"../chunk-7RMENK4B.mjs";import"../chunk-K7C7TUE5.mjs";import{TypedEmitter as nt}from"tiny-typed-emitter";import{TypedEmitter as st}from"tiny-typed-emitter";var rt={isLive:!0,dontResetOnZoneChange:!1,resetAfterPhaseTransition:!1,splitOnPhaseTransition:!1},F=class extends st{#t;encounters;#r;#n;#a;options;resetTimer;phaseTransitionResetRequest;phaseTransitionResetRequestTime;#s;constructor(a,r,i,t){super(),this.#r=a,this.#n=r,this.#a=i,this.options={...rt,...t},this.resetTimer=null,this.phaseTransitionResetRequest=!1,this.phaseTransitionResetRequestTime=0,this.#s=new Map,this.encounters=[],this.#t={startedOn:0,lastCombatPacket:0,fightStartedOn:0,localPlayer:this.#r.localPlayer.name,currentBoss:void 0,entities:new Map,damageStatistics:{totalDamageDealt:0,topDamageDealt:0,totalDamageTaken:0,topDamageTaken:0,totalHealingDone:0,topHealingDone:0,totalShieldDone:0,topShieldDone:0,debuffs:new Map,buffs:new Map,topShieldGotten:0,totalEffectiveShieldingDone:0,topEffectiveShieldingDone:0,topEffectiveShieldingUsed:0,effectiveShieldingBuffs:new Map,appliedShieldingBuffs:new Map}}}onCounterAttack(a,r){let i=this.updateEntity(a,{},r);i.hits.counter+=1}onInitEnv(a,r){this.options.isLive?(this.#t.entities.forEach((i,t,e)=>{i.hits.total===0&&e.delete(t)}),this.options.dontResetOnZoneChange===!1&&this.resetTimer===null&&(this.resetTimer=setTimeout(()=>{this.resetState(+r+6e3)},6e3),this.emit("message","new-zone"))):(this.splitEncounter(r),this.emit("message","new-zone"))}splitEncounter(a){if(this.#t.fightStartedOn!==0&&(this.#t.damageStatistics.totalDamageDealt!==0||this.#t.damageStatistics.totalDamageTaken!==0)){let r=structuredClone(this.#t);this.applyBreakdowns(r.entities),this.encounters.push(r)}this.resetState(+a)}getBossIfStillExist(){if(this.#t.currentBoss?.id){let a=BigInt(`0x0${this.#t.currentBoss?.id}`);return this.#r.entities.has(a)?this.#t.currentBoss:void 0}}resetState(a){this.cancelReset(),this.resetBreakdowns(),this.#t={startedOn:+a,lastCombatPacket:+a,fightStartedOn:0,localPlayer:this.#r.localPlayer.name,currentBoss:this.getBossIfStillExist(),entities:new Map,damageStatistics:{totalDamageDealt:0,topDamageDealt:0,totalDamageTaken:0,topDamageTaken:0,totalHealingDone:0,topHealingDone:0,totalShieldDone:0,topShieldDone:0,debuffs:new Map,buffs:new Map,appliedShieldingBuffs:new Map,effectiveShieldingBuffs:new Map,topEffectiveShieldingDone:0,topEffectiveShieldingUsed:0,topShieldGotten:0,totalEffectiveShieldingDone:0}},this.emit("reset-state",this.#t)}cancelReset(){this.resetTimer&&clearTimeout(this.resetTimer),this.resetTimer=null}onPhaseTransition(a,r){this.options.isLive&&(this.emit("message",`phase-transition-${a}`),this.options.resetAfterPhaseTransition&&(this.phaseTransitionResetRequest=!0,this.phaseTransitionResetRequestTime=+r)),!this.options.isLive&&this.options.splitOnPhaseTransition&&this.splitEncounter(r)}updateOptions(a){this.options={...this.options,...a}}onDeath(a,r){let i=this.#t.entities.get(a.name),t=0;i?i.isDead?t=i.deaths:t=i.deaths+1:t=1,this.updateEntity(a,{isDead:!0,deathTime:+r,deaths:t},r)}onDamage(a,r,i,t,e,s){if((t.modifier&15)===11&&t.skillId===0&&t.skillEffectId===0)return;this.phaseTransitionResetRequest&&this.phaseTransitionResetRequestTime>0&&this.phaseTransitionResetRequestTime<+s-8e3&&(this.resetState(+s),this.phaseTransitionResetRequest=!1);let[l,f]=this.#n.getStatusEffects(a,i,this.#r.localPlayer.characterId,s);if(this.#a.isBattleItem(t.skillEffectId,"attack")&&r&&r.entityType===5){let b=r;t.skillEffectId=b.skillEffectId}let o=this.updateEntity(a,{},s),E=this.updateEntity(i,{currentHp:t.targetCurHp,maxHp:t.targetMaxHp},s);if(!o||!E)return;!E.isPlayer&&t.targetCurHp<0&&(t.damage=t.damage+t.targetCurHp);let v=t.skillId;t.skillId===0&&t.skillEffectId!==0&&(v=t.skillEffectId);let h=o.skills.get(v);h||(h={...this.createEntitySkill(),id:v,...this.getSkillNameIcon(t.skillId,t.skillEffectId)},o.skills.set(v,h));let H=t.modifier&15,P=(t.modifier>>4&7)-1,R=(H&9)!==0,D=new Set,C=new Set;l.forEach(([b])=>{D.add(b)}),f.forEach(([b])=>{C.add(b)}),h.damageInfo.damageDealt+=t.damage,t.damage>h.maxDamage&&(h.maxDamage=t.damage),o.hits.total+=1,h.hits.total+=1,o.damageInfo.damageDealt+=t.damage,E.damageTaken+=t.damage;let K=R?1:0;o.hits.crit+=K,h.hits.crit+=K;let L=!1,j=!1,G=this.#a.getSkillEffectDirectionalMask(t.skillEffectId)-1;if(G===0||G===2){j=P===0;let b=j?1:0;o.hits.backAttack+=b,o.hits.totalBackAttack+=1,h.hits.backAttack+=b,h.hits.totalBackAttack+=1}if(G===1||G===2){L=P===1;let b=L?1:0;o.hits.frontAttack+=b,o.hits.totalFrontAttack+=1,h.hits.frontAttack+=b,h.hits.totalFrontAttack+=1}if(o.isPlayer){this.#t.damageStatistics.totalDamageDealt+=t.damage,this.#t.damageStatistics.topDamageDealt=Math.max(this.#t.damageStatistics.topDamageDealt,o.damageInfo.damageDealt);let b=!1,w=!1;D.forEach(n=>{if(!this.#t.damageStatistics.buffs.has(n)){let B=this.#a.getStatusEffectHeaderData(n);B&&this.#t.damageStatistics.buffs.set(n,B)}let I=this.#t.damageStatistics.buffs.get(n);I&&!b&&(b=(I.buffcategory==="classskill"||I.buffcategory==="identity"||I.buffcategory==="ability")&&I.source.skill!==void 0&&I.target===1&&this.#a.isSupportClassId(I.source.skill.classid));let M=h.damageDealtBuffedBy.get(n)??0;h.damageDealtBuffedBy.set(n,M+t.damage);let O=o.damageDealtBuffedBy.get(n)??0;o.damageDealtBuffedBy.set(n,O+t.damage);let T=o.hits.hitsBuffedBy.get(n)??0;o.hits.hitsBuffedBy.set(n,T+1);let x=h.hits.hitsBuffedBy.get(n)??0;h.hits.hitsBuffedBy.set(n,x+1)}),C.forEach(n=>{if(!this.#t.damageStatistics.debuffs.has(n)){let B=this.#a.getStatusEffectHeaderData(n);B&&this.#t.damageStatistics.debuffs.set(n,B)}let I=this.#t.damageStatistics.debuffs.get(n);I&&!w&&(w=(I.buffcategory==="classskill"||I.buffcategory==="identity"||I.buffcategory==="ability")&&I.source.skill!==void 0&&I.target===1&&this.#a.isSupportClassId(I.source.skill.classid));let M=h.damageDealtDebuffedBy.get(n)??0;h.damageDealtDebuffedBy.set(n,M+t.damage);let O=o.damageDealtDebuffedBy.get(n)??0;o.damageDealtDebuffedBy.set(n,O+t.damage);let T=o.hits.hitsDebuffedBy.get(n)??0;o.hits.hitsDebuffedBy.set(n,T+1);let x=h.hits.hitsDebuffedBy.get(n)??0;h.hits.hitsDebuffedBy.set(n,x+1)});let Y=w?1:0,$=b?1:0;if(h.damageInfo.damageDealtBuffedBySupport+=b?t.damage:0,h.damageInfo.damageDealtDebuffedBySupport+=w?t.damage:0,o.damageInfo.damageDealtBuffedBySupport+=b?t.damage:0,o.damageInfo.damageDealtDebuffedBySupport+=w?t.damage:0,o.hits.hitsBuffedBySupport+=$,o.hits.hitsDebuffedBySupport+=Y,h.hits.hitsBuffedBySupport+=$,h.hits.hitsDebuffedBySupport+=Y,t.damage>0&&o.isPlayer){let n={multDmg:{sumRate:0,totalRate:1,values:Array()},addDmg:{sumRate:0,values:Array()},crit:{sumRate:0,values:Array()},critDmgRate:2};if(l.forEach(([k,u,p])=>{let g=this.#r.entities.get(u);if(!g)return;let c=this.getBuffAfterTripods(this.#a.skillBuff.get(k),g,t);if(c){if(c.type==="skill_damage_amplify"&&c.statuseffectvalues&&g.entityType===1&&u!==a.entityId){let m=c.statuseffectvalues[0]??0,d=c.statuseffectvalues[4]??0;if((m===0||m===t.skillId)&&(d===0||d===t.skillEffectId)){let y=c.statuseffectvalues[1]??0;if(y!==0){let S=y/1e4*p;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}}}else c.type==="attack_power_amplify"&&c.statuseffectvalues&&g.entityType===1&&a.entityId;c.passiveoption.forEach(m=>{if(N[m.type]===2)if(g.entityType===1&&u!==a.entityId)if(m.keystat==="critical_hit_rate"){let d=m.value;if(d!==0){let y=d/1e4*p;n.crit.values.push({casterEntity:g,rate:y}),n.crit.sumRate+=y}}else if(m.keystat==="attack_power_sub_rate_2"){let d=m.value;if(d!==0){let y=d/1e4*p;n.addDmg.values.push({casterEntity:g,rate:y}),n.addDmg.sumRate+=y}}else if(m.keystat==="skill_damage_sub_rate_2"){let d=m.value;if(d!==0){let y=d/1e4*p;n.multDmg.values.push({casterEntity:g,rate:y}),n.multDmg.sumRate+=y,n.multDmg.totalRate*=1+y}}else m.keystat;else m.keystat==="critical_dam_rate"&&c.category==="buff"&&(n.critDmgRate+=m.value/1e4*p);else if(N[m.type]===4){let d=this.#a.combatEffect.get(m.keyindex);n.critDmgRate+=p*this.getCritMultiplierFromCombatEffect(d,{self:a,target:i,caster:g,skill:this.#a.skill.get(v),hitOption:P,targetCount:e})}})}}),f.forEach(([k,u,p])=>{let g=this.#r.entities.get(u);if(!g||g.entityType!==1||u===a.entityId)return;let c=this.getBuffAfterTripods(this.#a.skillBuff.get(k),g,t);if(c){if(c.type==="instant_stat_amplify"&&c.statuseffectvalues){let m=c.statuseffectvalues[0]??0;if(m!==0){let d=m/1e4*p;n.crit.values.push({casterEntity:g,rate:d}),n.crit.sumRate+=d}if(t.damageType===0){let d=c.statuseffectvalues[2]??0;if(d!==0){let S=-(d/1e4)*p*.5;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}let y=c.statuseffectvalues[7]??0;if(y!==0){let S=y/1e4*p;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}}else if(t.damageType===1){let d=c.statuseffectvalues[3]??0;if(d!==0){let S=-(d/1e4)*p*.5;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}let y=c.statuseffectvalues[8]??0;if(y!==0){let S=y/1e4*p;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}}}if(c.type==="skill_damage_amplify"&&c.statuseffectvalues){let m=c.statuseffectvalues[0]??0,d=c.statuseffectvalues[4]??0;if((m===0||m===t.skillId)&&(d===0||d===t.skillEffectId)){let y=c.statuseffectvalues[1]??0;if(y!==0){let S=y/1e4*p;n.multDmg.values.push({casterEntity:g,rate:S}),n.multDmg.sumRate+=S,n.multDmg.totalRate*=1+S}}}if(c.type==="directional_attack_amplify"&&c.statuseffectvalues){if(L){let m=c.statuseffectvalues[0]??0;if(m!==0){let d=m/1e4*p;n.multDmg.values.push({casterEntity:g,rate:d}),n.multDmg.sumRate+=d,n.multDmg.totalRate*=1+d}}if(j){let m=c.statuseffectvalues[4]??0;if(m!==0){let d=m/1e4*p;n.multDmg.values.push({casterEntity:g,rate:d}),n.multDmg.sumRate+=d,n.multDmg.totalRate*=1+d}}}}}),n.crit.values.length>0){let k=this.#a.skill.get(t.skillId);a.itemSet?.forEach(u=>{if(N[u.type]===2&&A[u.keystat]===76)n.critDmgRate+=u.value/1e4;else if(N[u.type]===4){let p=this.#a.combatEffect.get(u.keyindex);n.critDmgRate+=this.getCritMultiplierFromCombatEffect(p,{self:a,target:i,caster:a,skill:k,hitOption:P,targetCount:e})}a.skills.get(t.skillId)?.tripods.forEach(p=>{let g=new Map;p.options.forEach(c=>{let m=z[c.type];if(m===45){if((c.params[0]??0)===0||t.skillEffectId===(c.params[0]??0)){let d=c.params[1];if(d){let y=this.#a.combatEffect.get(d);y&&g.set(y.id,y)}}}else if(m===46)g.delete(c.params[0]??0);else if(m===104){if((c.params[0]??0)===0||t.skillEffectId===(c.params[0]??0)){let d=g.get(c.params[1]??0);if(d){let y=structuredClone(d);g.set(d.id,y),y.effects.forEach(S=>{S.actions.forEach(J=>{for(let _=0;_<c.params.length-2;_++)Z[c.paramtype]===1?J.args[_]*=1+(c.params[_+2]??0)/100:J.args[_]+=c.params[_+2]??0})})}}}else m===29&&((c.params[0]??0)===0||t.skillEffectId===(c.params[0]??0))&&(n.critDmgRate+=(c.params[1]??0)/1e4)}),g.forEach(c=>{n.critDmgRate+=this.getCritMultiplierFromCombatEffect(c,{self:a,target:i,caster:a,skill:k,hitOption:P,targetCount:e})})})})}let I=0;if(n.crit.values.length>0){let k,u;R?(k=t.damage,u=k/n.critDmgRate):(u=t.damage,k=u*n.critDmgRate),I=(k-u)/k*n.crit.sumRate}let M=(1+I)*(1+n.addDmg.sumRate)*n.multDmg.totalRate-1,O=I+n.addDmg.sumRate+(n.multDmg.totalRate-1),T=M*t.damage/(O*(1+M)),x=I*T/n.crit.sumRate;n.crit.values.forEach(k=>{let u=k.rate*x,p=this.#t.entities.get(k.casterEntity.name);p&&(p.damageInfo.rdpsDamageGiven+=u),o.damageInfo.rdpsDamageReceived+=u,h.damageInfo.rdpsDamageReceived+=u}),n.addDmg.values.forEach(k=>{let u=k.rate*T,p=this.#t.entities.get(k.casterEntity.name);p&&(p.damageInfo.rdpsDamageGiven+=u),o.damageInfo.rdpsDamageReceived+=u,h.damageInfo.rdpsDamageReceived+=u});let B=(n.multDmg.totalRate-1)*T/n.multDmg.sumRate;n.multDmg.values.forEach(k=>{let u=k.rate*B,p=this.#t.entities.get(k.casterEntity.name);p&&(p.damageInfo.rdpsDamageGiven+=u),o.damageInfo.rdpsDamageReceived+=u,h.damageInfo.rdpsDamageReceived+=u})}let at={timestamp:+s,damage:t.damage,targetEntity:E.id,isCrit:R,isBackAttack:j,isFrontAttack:L,isBuffedBySupport:b,isDebuffedBySupport:w,buffedBy:[...D],debuffedBy:[...C]},it=BigInt("0x"+o.id);this.addBreakdown(it,v,at)}E.isPlayer&&(this.#t.damageStatistics.totalDamageTaken+=t.damage,this.#t.damageStatistics.topDamageTaken=Math.max(this.#t.damageStatistics.topDamageTaken,E.damageTaken)),E.isBoss&&(this.#t.currentBoss=E),this.#t.fightStartedOn===0&&(this.#t.fightStartedOn=+s),this.#t.lastCombatPacket=+s}getBuffAfterTripods(a,r,i){if(!a||r.entityType!==1)return a;let t=structuredClone(a);return r.skills.get(i.skillId)?.tripods.forEach(e=>{e.options.forEach(s=>{let l=z[s.type];if(l===19){if(((s.params[0]??0)===0||i.skillEffectId===(s.params[0]??0))&&t.id===(s.params[1]??0)){let f=new Map;for(let o=2;o<s.params.length;o+=2)s.params[o]&&s.params[o+1]&&f.set(s.params[o]??0,s.params[o+1]??0);t.passiveoption.forEach(o=>{let E=f.get(A[o.keystat]);N[o.type]===2&&E&&(Z[s.paramtype]===0?o.value+=E:o.value*=1+E/100)})}}else if(l===42){if(((s.params[0]??0)===0||i.skillEffectId===(s.params[0]??0))&&t.id===(s.params[1]??0)){let f=A[s.params[2]??0],o=s.params[3]??0;f&&o!==void 0&&t.passiveoption.push({type:"stat",keystat:f,keyindex:0,value:o})}}else if(l===21&&t.statuseffectvalues&&((s.params[0]??0)===0||i.skillEffectId===(s.params[0]??0))&&t.id===(s.params[1]??0))if((s.paramtype[2]??0)===0)t.statuseffectvalues=s.params.slice(3);else{let f=[];for(let o=0;o<Math.max(t.statuseffectvalues.length,s.params.length-3);o++)s.params[o+3]&&f.push((t.statuseffectvalues[o]??0)*(1+(s.params[o+3]??0)/100));t.statuseffectvalues=f}})}),t}getCritMultiplierFromCombatEffect(a,r){if(!a)return 0;let i=0;return a.effects.filter(t=>t.actions.find(e=>V[e.type]===4)).forEach(t=>{this.#a.isCombatEffectConditionsValid({effect:t,...r})&&t.actions.filter(e=>V[e.type]===4).forEach(e=>{i+=(e.args[0]??0)/100})}),i}onStartSkill(a,r,i){let t=this.updateEntity(a,{isDead:!1},i);if(t){t.hits.casts+=1;let e=t.skills.get(r);e||(e={...this.createEntitySkill(),id:r,...this.getSkillNameIcon(r,0)},t.skills.set(r,e)),e.hits.casts+=1}}onShieldUsed(a,r,i,t){if(t<0&&console.error("Shield change values was negative, shield ammount increased"),a.entityType===1&&r.entityType===1){if(!this.#t.damageStatistics.effectiveShieldingBuffs.has(i)){let E=this.#a.getStatusEffectHeaderData(i);E&&this.#t.damageStatistics.effectiveShieldingBuffs.set(i,E)}let e=new Date,s=this.updateEntity(a,{},e),l=this.updateEntity(r,{},e);s.damagePreventedByShield+=t;let f=s.damagePreventedByShieldBy.get(i)??0;s.damagePreventedByShieldBy.set(i,f+t),this.#t.damageStatistics.topEffectiveShieldingUsed=Math.max(s.damagePreventedByShield,this.#t.damageStatistics.topEffectiveShieldingUsed),l.damagePreventedWithShieldOnOthers+=t;let o=l.damagePreventedWithShieldOnOthersBy.get(i)??0;l.damagePreventedWithShieldOnOthersBy.set(i,o+t),this.#t.damageStatistics.topEffectiveShieldingDone=Math.max(l.damagePreventedWithShieldOnOthers,this.#t.damageStatistics.topEffectiveShieldingDone),this.#t.damageStatistics.totalEffectiveShieldingDone+=t}}onShieldApplied(a,r,i,t){let e=new Date,s=this.updateEntity(a,{},e),l=this.updateEntity(r,{},e);if(l.isPlayer&&s.isPlayer){if(!this.#t.damageStatistics.appliedShieldingBuffs.has(i)){let E=this.#a.getStatusEffectHeaderData(i);E&&this.#t.damageStatistics.appliedShieldingBuffs.set(i,E)}s.shieldReceived+=t,l.shieldDone+=t;let f=l.shieldDoneBy.get(i)??0;l.shieldDoneBy.set(i,f+t);let o=s.shieldReceivedBy.get(i)??0;s.shieldReceivedBy.set(i,o+t),this.#t.damageStatistics.topShieldDone=Math.max(l.shieldDone,this.#t.damageStatistics.topShieldDone),this.#t.damageStatistics.topShieldGotten=Math.max(s.shieldReceived,this.#t.damageStatistics.topShieldGotten),this.#t.damageStatistics.totalShieldDone+=t}}getSkillNameIcon(a,r){if(a===0&&r===0)return{name:"Bleed",icon:"buff_168.png"};if(a===0){let i=this.#a.skillEffect.get(r);if(i&&i.itemname)return{name:i.itemname,icon:i.icon??""};if(i){if(i.sourceskill){let t=this.#a.skill.get(i.sourceskill);if(t)return{name:t.name,icon:t.icon}}else{let t=this.#a.skill.get(Math.floor(r/10));if(t)return{name:t.name,icon:t.icon}}return{name:i.comment}}else return{name:this.#a.getSkillName(a)}}else{let i=this.#a.skill.get(a);return!i&&(i=this.#a.skill.get(a-a%10),!i)?{name:this.#a.getSkillName(a),icon:""}:i.summonsourceskill?(i=this.#a.skill.get(i.summonsourceskill),i?{name:i.name+" (Summon)",icon:i.icon}:{name:this.#a.getSkillName(a),icon:""}):i.sourceskill?(i=this.#a.skill.get(i.sourceskill),i?{name:i.name,icon:i.icon}:{name:this.#a.getSkillName(a),icon:""}):{name:i.name,icon:i.icon}}}updateEntity(a,r,i){let t={lastUpdate:+i},e=this.#t.entities.get(a.name),s={};if(!e||a.entityType===1&&e.isPlayer!==!0){if(a.entityType===1){let l=a;s={classId:l.class,gearScore:l.gearLevel,isPlayer:!0}}else if(a.entityType===2||a.entityType===3){let l=a;s={npcId:l.typeId,isBoss:l.isBoss}}else if(a.entityType===4){let l=a;s={npcId:l.typeId,isBoss:l.isBoss,isEsther:!0,icon:l.icon}}}return e?Object.assign(e,r,t,s):(e={...this.createEntity(),...r,...t,...s,name:a.name,id:a.entityId.toString(16)},this.#t.entities.set(a.name,e)),e}updateOrCreateEntity(a,r,i){if(!(!r.name||!r.id)){for(let[t,e]of this.#t.entities)if(r.id===e.id){this.#t.entities.delete(t),this.updateEntity(a,{...e,...r},i);return}this.updateEntity(a,r,i)}}createEntitySkill(){return{id:0,name:"",icon:"",damageInfo:{damageDealt:0,rdpsDamageReceived:0,rdpsDamageGiven:0,damageDealtDebuffedBySupport:0,damageDealtBuffedBySupport:0},maxDamage:0,hits:{casts:0,total:0,crit:0,backAttack:0,totalBackAttack:0,frontAttack:0,totalFrontAttack:0,counter:0,hitsDebuffedBySupport:0,hitsBuffedBySupport:0,hitsBuffedBy:new Map,hitsDebuffedBy:new Map},breakdown:[],damageDealtDebuffedBy:new Map,damageDealtBuffedBy:new Map}}createEntity(){return{lastUpdate:0,id:"",npcId:0,name:"",classId:0,isBoss:!1,isPlayer:!1,isDead:!1,deaths:0,deathTime:0,gearScore:0,currentHp:0,maxHp:0,damageInfo:{damageDealt:0,rdpsDamageReceived:0,rdpsDamageGiven:0,damageDealtDebuffedBySupport:0,damageDealtBuffedBySupport:0},healingDone:0,shieldDone:0,damageTaken:0,skills:new Map,hits:{casts:0,total:0,crit:0,backAttack:0,totalBackAttack:0,frontAttack:0,totalFrontAttack:0,counter:0,hitsDebuffedBySupport:0,hitsBuffedBySupport:0,hitsBuffedBy:new Map,hitsDebuffedBy:new Map},damageDealtDebuffedBy:new Map,damageDealtBuffedBy:new Map,damagePreventedByShieldBy:new Map,damagePreventedWithShieldOnOthersBy:new Map,shieldDoneBy:new Map,shieldReceivedBy:new Map,damagePreventedWithShieldOnOthers:0,damagePreventedByShield:0,shieldReceived:0}}getBroadcast(){let a={...this.#t};return a.entities=new Map,this.#t.entities.forEach((r,i)=>{!r.isPlayer&&!r.isEsther||a.entities.set(i,{...r})}),a.localPlayer=this.#r.localPlayer.name,a}resetBreakdowns(){this.#s.clear()}createBreakdownEntity(a){return this.#s.has(a)||this.#s.set(a,new Map),this.#s.get(a)}removeBreakdownEntry(a){this.#s.delete(a)}addBreakdown(a,r,i){let t=this.createBreakdownEntity(a);if(t.has(r))t.get(r).push(i);else{let e=new Array(i);t.set(r,e)}}getBreakdowns(a,r){let i=this.#s.get(a);if(i)return i.get(r)}clearBreakdowns(a,r){let i=this.#s.get(a);i&&i.delete(r)}applyBreakdowns(a,r=!0){a.forEach(i=>{i.skills.forEach(t=>{let e=BigInt("0x"+i.id),s=this.getBreakdowns(e,t.id);s&&(t.breakdown=[...s])})}),r&&this.resetBreakdowns()}};var U=class{characterIdToPartyId;entityIdToPartyId;raidInstanceToPartyInstances;ownName;characterNameToCharacterId;#t;constructor(a){this.characterIdToPartyId=new Map,this.entityIdToPartyId=new Map,this.raidInstanceToPartyInstances=new Map,this.characterNameToCharacterId=new Map,this.#t=a}add(a,r,i=void 0,t=void 0,e=void 0){!i&&!t||(i&&!t&&(t=this.#t.getEntityId(i)),t&&!i&&(i=this.#t.getEntityId(t)),i&&this.characterIdToPartyId.set(i,r),t&&this.entityIdToPartyId.set(t,r),e&&i&&this.characterNameToCharacterId.set(e,i),this.registerPartyId(a,r))}completeEntry(a,r){let i=this.getPartyIdFromCharacterId(a),t=this.getPartyIdFromEntityId(r);i&&t||(!i&&t&&this.characterIdToPartyId.set(a,t),!t&&i&&this.entityIdToPartyId.set(r,i))}changeEntityId(a,r){let i=this.getPartyIdFromEntityId(a);i&&(this.entityIdToPartyId.delete(a),this.entityIdToPartyId.set(r,i))}setOwnName(a){this.ownName=a}remove(a,r){if(r===this.ownName){this.removePartyMappings(a);return}let i=this.characterNameToCharacterId.get(r);if(this.characterNameToCharacterId.delete(r),!i)return;this.characterIdToPartyId.delete(i);let t=this.#t.getEntityId(i);t&&this.characterIdToPartyId.delete(t)}isCharacterInParty(a){return this.characterIdToPartyId.has(a)}isEntityInParty(a){return this.entityIdToPartyId.has(a)}getPartyIdFromCharacterId(a){return this.characterIdToPartyId.get(a)}getPartyIdFromEntityId(a){return this.entityIdToPartyId.get(a)}removePartyMappings(a){let r=this.getRaidInstanceId(a),i=r?this.raidInstanceToPartyInstances.get(r)??new Set([a]):new Set([a]);for(let[t,e]of this.characterIdToPartyId)if(i.has(e)){this.characterIdToPartyId.delete(t);for(let[s,l]of this.characterNameToCharacterId)if(t===l){this.characterNameToCharacterId.delete(s);break}}for(let[t,e]of this.entityIdToPartyId)i.has(e)&&this.entityIdToPartyId.delete(t)}getRaidInstanceId(a){for(let r of this.raidInstanceToPartyInstances)if(r[1].has(a))return r[0]}registerPartyId(a,r){let i=this.raidInstanceToPartyInstances.get(a);i||(i=new Set,this.raidInstanceToPartyInstances.set(a,i)),i.add(r)}partyInfo(a,r,i){let t=a.parsed;if(t){if(t.memberDatas.length===1&&t.memberDatas[0]?.name===i.name){this.remove(t.partyInstanceId,t.memberDatas[0].name);return}this.removePartyMappings(t.partyInstanceId);for(let e of t.memberDatas){e.characterId===i.characterId&&this.setOwnName(e.name);let s=this.#t.getEntityId(e.characterId);if(s){let l=r.get(s);if(l&&l.entityType===1&&l.name!==e.name){let f=l;f.gearLevel=e.gearLevel,f.name=e.name,f.class=e.classId}}this.add(t.raidInstanceId,t.partyInstanceId,e.characterId,s,e.name)}}}};var q=class{entityToCharacterId;characterToEntityId;constructor(){this.entityToCharacterId=new Map,this.characterToEntityId=new Map}addMapping(a,r){this.entityToCharacterId.set(r,a),this.characterToEntityId.set(a,r)}getCharacterId(a){return this.entityToCharacterId.get(a)}getEntityId(a){return this.characterToEntityId.get(a)}clear(){this.entityToCharacterId.clear(),this.characterToEntityId.clear()}};var et=class extends nt{#t;#r;#n;#a;#s;#e;#i;#o;#l;constructor(a,r,i){super(),this.#t=a,this.#r=r,this.#n=new q,this.#a=new U(this.#n),this.#s=new Q(this.#a,this.#r,i.isLive??!0),this.#e=new X(this.#n,this.#a,this.#s,this.#r),this.#i=new F(this.#e,this.#s,this.#r,i),this.#i.emit=this.emit.bind(this),this.#o=!1,this.#l=!1,this.#i.options.isLive&&setInterval(this.broadcastStateChange.bind(this),100),this.#t.on("AbilityChangeNotify",t=>{}).on("ActiveAbilityNotify",t=>{}).on("AddonSkillFeatureChangeNotify",t=>{}).on("BlockSkillStateNotify",t=>{}).on("CounterAttackNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.entities.get(e.sourceId);s&&this.#i.onCounterAttack(s,t.time)}).on("DeathNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.entities.get(e.targetId);s&&this.#i.onDeath(s,t.time)}).on("EquipChangeNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.entities.get(e.objectId);!s||s.entityType!==1||(s.itemSet=this.#e.getPlayerSetOptions(e.equipItemDataList))}).on("IdentityStanceChangeNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.entities.get(e.objectId);s&&s.entityType===1&&(s.stance=e.stance)}).on("IdentityGaugeChangeNotify",t=>{}).on("InitAbility",t=>{}).on("InitEnv",t=>{this.#e.processInitEnv(t),this.#i.onInitEnv(t,t.time)}).on("InitLocal",t=>{}).on("InitPC",t=>{let e=this.#e.processInitPC(t);if(e&&t.parsed){let s=this.#r.getStatPairMap(t.parsed.statPair);this.#i.updateOrCreateEntity(e,{id:e.entityId.toString(16),name:e.name,classId:e.class,isPlayer:!0,gearScore:e.gearLevel,currentHp:Number(s.get(1))||0,maxHp:Number(s.get(27))||0},t.time)}}).on("InitItem",t=>{let e=t.parsed;!e||e.storageType!==1||(this.#e.localPlayer.itemSet=this.#e.getPlayerSetOptions(e.itemDataList))}).on("MigrationExecute",t=>{if(this.#e.localPlayer.characterId!==0n)return;let e=t.parsed;e&&(this.#e.localPlayer.characterId=e.account_CharacterId1<e.account_CharacterId2?e.account_CharacterId1:e.account_CharacterId2)}).on("NewNpc",t=>{let e=this.#e.processNewNpc(t);if(e&&t.parsed){let s=this.#r.getStatPairMap(t.parsed.npcStruct.statPair);this.#i.updateOrCreateEntity(e,{id:e.entityId.toString(16),name:e.name,npcId:e.typeId,isPlayer:!1,isBoss:e.isBoss,currentHp:Number(s.get(1))||0,maxHp:Number(s.get(27))||0},t.time)}}).on("NewNpcSummon",t=>{let e=this.#e.processNewNpcSummon(t);if(e&&t.parsed){let s=this.#r.getStatPairMap(t.parsed.npcData.statPair);this.#i.updateOrCreateEntity(e,{id:e.entityId.toString(16),name:e.name,npcId:e.typeId,isPlayer:!1,isBoss:e.isBoss,currentHp:Number(s.get(1))||0,maxHp:Number(s.get(27))||0},t.time)}}).on("NewPC",t=>{let e=this.#e.processNewPC(t);if(e&&t.parsed){e.itemSet=this.#e.getPlayerSetOptions(t.parsed.pcStruct.equipItemDataList);let s=this.#r.getStatPairMap(t.parsed.pcStruct.statPair);this.#i.updateOrCreateEntity(e,{id:e.entityId.toString(16),name:e.name,classId:e.class,isPlayer:!0,gearScore:e.gearLevel,currentHp:Number(s.get(1))||0,maxHp:Number(s.get(27))||0},t.time)}}).on("NewProjectile",t=>{let e=t.parsed;if(!e)return;let s={entityId:e.projectileInfo.projectileId,entityType:5,name:e.projectileInfo.projectileId.toString(16),ownerId:e.projectileInfo.ownerId,skillEffectId:e.projectileInfo.skillEffect,skillId:e.projectileInfo.skillId,stats:new Map};this.#e.entities.set(s.entityId,s)}).on("ParalyzationStateNotify",t=>{}).on("PartyInfo",t=>{this.#a.partyInfo(t,this.#e.entities,this.#e.localPlayer)}).on("PartyLeaveResult",t=>{let e=t.parsed;e&&this.#a.remove(e.partyInstanceId,e.name)}).on("PartyPassiveStatusEffectAddNotify",t=>{}).on("PartyPassiveStatusEffectRemoveNotify",t=>{}).on("PartyStatusEffectAddNotify",t=>{let e=t.parsed;if(e)for(let s of e.statusEffectDatas){let l=e.playerIdOnRefresh!==0n?e.playerIdOnRefresh:s.sourceId,f=this.#e.getSourceEntity(l);this.#s.RegisterStatusEffect(this.#s.buildStatusEffect(s,e.characterId,f.entityId,0,t.time))}}).on("PartyStatusEffectRemoveNotify",t=>{let e=t.parsed;if(e)for(let s of e.statusEffectIds)this.#s.RemoveStatusEffect(e.characterId,s,0,e.reason,t.time)}).on("PartyStatusEffectResultNotify",t=>{let e=t.parsed;e&&this.#a.add(e.raidInstanceId,e.partyInstanceId,e.characterId)}).on("PassiveStatusEffectAddNotify",t=>{}).on("PassiveStatusEffectRemoveNotify",t=>{}).on("RaidBossKillNotify",t=>{this.#i.onPhaseTransition(1,t.time)}).on("RaidResult",t=>{this.#i.onPhaseTransition(0,t.time)}).on("RemoveObject",t=>{let e=t.parsed;if(e)for(let s of e.unpublishedObjects)this.#s.RemoveLocalObject(s.objectId,t.time)}).on("SkillCastNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.getSourceEntity(e.caster);s=this.#e.guessIsPlayer(s,e.skillId),this.#i.onStartSkill(s,e.skillId,t.time)}).on("SkillDamageAbnormalMoveNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.getSourceEntity(e.sourceId);e.skillDamageAbnormalMoveEvents.forEach(l=>{let f=this.#e.getOrCreateEntity(l.skillDamageEvent.targetId),o=this.#e.getOrCreateEntity(e.sourceId);f.stats.set(1,l.skillDamageEvent.curHp),f.stats.set(27,l.skillDamageEvent.maxHp),this.#i.onDamage(s,o,f,{skillId:e.skillId,skillEffectId:e.skillEffectId,damage:Number(l.skillDamageEvent.damage),modifier:l.skillDamageEvent.modifier,targetCurHp:Number(l.skillDamageEvent.curHp),targetMaxHp:Number(l.skillDamageEvent.maxHp),damageAttr:l.skillDamageEvent.damageAttr??0,damageType:l.skillDamageEvent.damageType},e.skillDamageAbnormalMoveEvents.length,t.time)})}).on("SkillDamageNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.getSourceEntity(e.sourceId);e.skillDamageEvents.forEach(l=>{let f=this.#e.getOrCreateEntity(l.targetId),o=this.#e.getOrCreateEntity(e.sourceId);this.#i.onDamage(s,o,f,{skillId:e.skillId,skillEffectId:e.skillEffectId,damage:Number(l.damage),modifier:l.modifier,targetCurHp:Number(l.curHp),targetMaxHp:Number(l.maxHp),damageAttr:l.damageAttr??0,damageType:l.damageType},e.skillDamageEvents.length,t.time)})}).on("SkillStageNotify",t=>{}).on("SkillStartNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.getSourceEntity(e.sourceId);if(s=this.#e.guessIsPlayer(s,e.skillId),s.entityType===1){let l=s,f=l.skills.get(e.skillId);if(f||(f={effects:new Set,tripods:new Map},l.skills.set(e.skillId,f)),f.level=e.skillLevel,e.skillOptionData.tripodIndex&&e.skillOptionData.tripodLevel){f.tripods||(f.tripods=new Map);for(let[o,E]of["first","second","third"].entries()){if(e.skillOptionData.tripodIndex[E]===0){for(let D=1;D<=3;D++)f.tripods.delete(3*o+D);continue}let v=3*o+e.skillOptionData.tripodIndex[E],h=e.skillOptionData.tripodLevel[E],H=f.tripods.get(v);if(H&&h===H.level)continue;for(let D=1;D<=3;D++)f.tripods.delete(3*o+D);let P=this.#r.skillFeature.get(e.skillId)?.get(v),R=[];P&&P.entries.forEach(D=>{D.level!==0&&D.level!==h||R.push(D)}),f.tripods.set(v,{level:e.skillOptionData.tripodLevel[E],options:R.sort((D,C)=>C.level-D.level)})}}}this.#i.onStartSkill(s,e.skillId,t.time)}).on("StatusEffectAddNotify",t=>{let e=t.parsed;if(!e)return;let s=this.#e.getSourceEntity(e.statusEffectData.sourceId);this.#s.RegisterStatusEffect(this.#s.buildStatusEffect(e.statusEffectData,e.objectId,s.entityId,1,t.time))}).on("StatusEffectDurationNotify",t=>{let e=t.parsed;e&&this.#s.UpdateDuration(e.effectInstanceId,e.targetId,e.expirationTick,1)}).on("StatusEffectRemoveNotify",t=>{let e=t.parsed;if(e)for(let s of e.statusEffectIds)this.#s.RemoveStatusEffect(e.objectId,s,1,e.reason,t.time)}).on("StatusEffectSyncDataNotify",t=>{let e=t.parsed;e&&this.#s.SyncStatusEffect(e.effectInstanceId,e.characterId,e.objectId,e.value,this.#e.localPlayer.characterId)}).on("TriggerBossBattleStatus",t=>{this.#i.onPhaseTransition(2,t.time)}).on("TriggerFinishNotify",t=>{}).on("TriggerStartNotify",t=>{let e=t.parsed;if(e)switch(e.triggerSignalType){case 57:case 59:case 61:case 63:case 74:case 76:this.#l=!0,this.#o=!1;break;case 58:case 60:case 62:case 64:case 75:case 77:this.#l=!1,this.#o=!0;break}}).on("TroopMemberUpdateMinNotify",t=>{}).on("ZoneObjectUnpublishNotify",t=>{let e=t.parsed;e&&this.#s.RemoveLocalObject(e.objectId,t.time)}).on("ZoneStatusEffectAddNotify",t=>{}).on("TroopMemberUpdateMinNotify",t=>{let e=t.parsed;if(e&&e.statusEffectDatas.length>0)for(let s of e.statusEffectDatas){let l=this.#n.getEntityId(e.characterId),f=s.value?s.value.readUInt32LE():0,o=s.value?s.value.readUInt32LE(8):0,E=f<o?f:o;this.#s.SyncStatusEffect(s.effectInstanceId,e.characterId,l,E,this.#e.localPlayer.characterId)}}).on("ZoneStatusEffectRemoveNotify",t=>{}),this.#s.on("shieldApplied",t=>{let e=t.targetId;if(t.type===0&&(e=this.#n.getEntityId(t.targetId)??e),e===void 0)return;let s=this.#e.getSourceEntity(t.sourceId),l=this.#e.getOrCreateEntity(e);this.#i.onShieldApplied(l,s,t.statusEffectId,t.value)}).on("shieldChanged",(t,e,s)=>{let l=t.targetId;if(t.type===0&&(l=this.#n.getEntityId(t.targetId)??l),l===void 0)return;let f=this.#e.getSourceEntity(t.sourceId),o=this.#e.getOrCreateEntity(l);this.#i.onShieldUsed(o,f,t.statusEffectId,e-s)})}broadcastStateChange(){this.emit("state-change",this.#i.getBroadcast())}reset(){this.#i.resetState(+new Date)}cancelReset(){this.#i.cancelReset()}updateOptions(a){this.#i.updateOptions(a)}get encounters(){return this.#i.splitEncounter(new Date),this.#i.encounters}};export{et as Parser};
