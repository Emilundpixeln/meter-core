var B=Object.defineProperty;var Q=Object.getOwnPropertyDescriptor;var X=Object.getOwnPropertyNames;var $=Object.prototype.hasOwnProperty;var g=(v,r,n)=>r in v?B(v,r,{enumerable:!0,configurable:!0,writable:!0,value:n}):v[r]=n;var t=(v,r)=>{for(var n in r)B(v,n,{get:r[n],enumerable:!0})},y=(v,r,n,a)=>{if(r&&typeof r=="object"||typeof r=="function")for(let h of X(r))!$.call(v,h)&&h!==n&&B(v,h,{get:()=>r[h],enumerable:!(a=Q(r,h))||a.enumerable});return v};var __=v=>y(B({},"__esModule",{value:!0}),v);var M=(v,r,n)=>(g(v,typeof r!="symbol"?r+"":r,n),n),F=(v,r,n)=>{if(!r.has(v))throw TypeError("Cannot "+n)};var w=(v,r,n)=>(F(v,r,"read from private field"),n?n.call(v):r.get(v)),R=(v,r,n)=>{if(r.has(v))throw TypeError("Cannot add the same private member more than once");r instanceof WeakSet?r.add(v):r.set(v,n)},A=(v,r,n,a)=>(F(v,r,"write to private field"),a?a.call(v,n):r.set(v,n),n);var O=(v,r,n)=>(F(v,r,"access private method"),n);var l_={};t(l_,{MeterData:()=>K});module.exports=__(l_);var I=require("fs"),x=require("path");var V=(u=>(u[u.none=0]="none",u[u.slot=1]="slot",u[u.stat=2]="stat",u[u.ability_point=3]="ability_point",u[u.combat_effect=4]="combat_effect",u[u.skill_damage=5]="skill_damage",u[u.skill_critical_ratio=6]="skill_critical_ratio",u[u.skill_critical_damage=7]="skill_critical_damage",u[u.skill_penetration=8]="skill_penetration",u[u.npc_grade_less_damage=9]="npc_grade_less_damage",u[u.npc_grade_less_critical_ratio=10]="npc_grade_less_critical_ratio",u[u.npc_grade_less_critical_damage=11]="npc_grade_less_critical_damage",u[u.npc_grade_less_penetration=12]="npc_grade_less_penetration",u[u.npc_grade_greater_damage=13]="npc_grade_greater_damage",u[u.npc_grade_greater_critical_ratio=14]="npc_grade_greater_critical_ratio",u[u.npc_grade_greater_critical_damage=15]="npc_grade_greater_critical_damage",u[u.npc_grade_greater_penetration=16]="npc_grade_greater_penetration",u[u.npc_species_damage=17]="npc_species_damage",u[u.npc_species_critical_ratio=18]="npc_species_critical_ratio",u[u.npc_species_critical_damage=19]="npc_species_critical_damage",u[u.npc_species_penetration=20]="npc_species_penetration",u[u.npc_attr_damage=21]="npc_attr_damage",u[u.npc_attr_critical_ratio=22]="npc_attr_critical_ratio",u[u.npc_attr_critical_damage=23]="npc_attr_critical_damage",u[u.npc_attr_penetration=24]="npc_attr_penetration",u[u.mana_reduction=25]="mana_reduction",u[u.skill_mana_reduction=26]="skill_mana_reduction",u[u.skill_cooldown_reduction=27]="skill_cooldown_reduction",u[u.ability_feature=28]="ability_feature",u[u.class_option=29]="class_option",u[u.ability_point_passive=30]="ability_point_passive",u[u.instrument=31]="instrument",u[u.skill_feature=32]="skill_feature",u[u.npc_adaptation=33]="npc_adaptation",u[u.skill_group_damage=34]="skill_group_damage",u[u.skill_group_cooldown_reduction=35]="skill_group_cooldown_reduction",u[u.skill_level=36]="skill_level",u[u.skill_feature_level=37]="skill_feature_level",u[u.life_casting_speed=38]="life_casting_speed",u[u.life_casting_tier=39]="life_casting_tier",u[u.life_bonus_type_success=40]="life_bonus_type_success",u[u.life_bonus_type_extra=41]="life_bonus_type_extra",u[u.life_bonus_type_skill_bonus=42]="life_bonus_type_skill_bonus",u[u.life_bonus_type_minigame_perfect=43]="life_bonus_type_minigame_perfect",u[u.life_durability_bonus=44]="life_durability_bonus",u[u.life_mini_game_difficulty=45]="life_mini_game_difficulty",u[u.combat_effect_cooldown_reduction=46]="combat_effect_cooldown_reduction",u[u.skill_damage_addend=47]="skill_damage_addend",u[u.awakening_usable_count_addend=48]="awakening_usable_count_addend",u[u.battle_item_heal=49]="battle_item_heal",u[u.party_heal=50]="party_heal",u[u.party_shield=51]="party_shield",u[u.identity_gauge=52]="identity_gauge",u[u.attack_power_amplify_addend=53]="attack_power_amplify_addend",u[u.attack_power_amplify_multiplier=54]="attack_power_amplify_multiplier",u[u.not_in_party_damage=55]="not_in_party_damage",u[u.skill_effect_group_set_damage=56]="skill_effect_group_set_damage",u))(V||{});var G=(m=>(m[m.none=0]="none",m[m.modify_damage=1]="modify_damage",m[m.modify_final_damage=2]="modify_final_damage",m[m.modify_critical_ratio=3]="modify_critical_ratio",m[m.modify_critical_multiplier=4]="modify_critical_multiplier",m[m.modify_penetration=5]="modify_penetration",m[m.modify_penetration_when_critical=6]="modify_penetration_when_critical",m[m.exec_active_effect_when_damage=7]="exec_active_effect_when_damage",m[m.exec_active_effect_when_critical=8]="exec_active_effect_when_critical",m[m.exec_reactive_effect_when_miss=9]="exec_reactive_effect_when_miss",m[m.exec_reactive_effect_when_damage=10]="exec_reactive_effect_when_damage",m[m.exec_reactive_effect_when_critical=11]="exec_reactive_effect_when_critical",m[m.exec_after_effect=12]="exec_after_effect",m[m.exec_after_skill=13]="exec_after_skill",m[m.apply_heal=14]="apply_heal",m[m.modify_reactive_damage=15]="modify_reactive_damage",m[m.modify_damage_shield_multiplier=16]="modify_damage_shield_multiplier",m[m.exec_active_effect_when_kill=17]="exec_active_effect_when_kill",m[m.exec_start_skill=18]="exec_start_skill",m[m.modify_penetration_addend=19]="modify_penetration_addend",m[m.modify_penetration_addend_when_critical=20]="modify_penetration_addend_when_critical",m[m.modify_reactive_critical_multiplier=21]="modify_reactive_critical_multiplier",m[m.modify_damage_when_critical=22]="modify_damage_when_critical",m[m.modify_paralyzation_point=23]="modify_paralyzation_point",m))(G||{}),U=(h=>(h[h.none=0]="none",h[h.self=1]="self",h[h.target=2]="target",h[h.caster=3]="caster",h))(U||{}),H=(d=>(d[d.none=0]="none",d[d.current_skill=1]="current_skill",d[d.hp_less=2]="hp_less",d[d.hp_greater=3]="hp_greater",d[d.mp_less=4]="mp_less",d[d.mp_greater=5]="mp_greater",d[d.npc_grade_less=6]="npc_grade_less",d[d.npc_grade_greater=7]="npc_grade_greater",d[d.npc_grade_equal=8]="npc_grade_equal",d[d.npc_species=9]="npc_species",d[d.npc_attr=10]="npc_attr",d[d.abnormal_move=11]="abnormal_move",d[d.abnormal_status=12]="abnormal_status",d[d.abnormal_move_immune=13]="abnormal_move_immune",d[d.abnormal_status_immune=14]="abnormal_status_immune",d[d.abnormal_move_all=15]="abnormal_move_all",d[d.pc=16]="pc",d[d.skill_effect_id=17]="skill_effect_id",d[d.identity_stack_count=18]="identity_stack_count",d[d.status_effect_immunetype=19]="status_effect_immunetype",d[d.abnormal_not_move=20]="abnormal_not_move",d[d.target_count=21]="target_count",d[d.skill_identity_category=22]="skill_identity_category",d[d.identity_element_value=23]="identity_element_value",d[d.directional_attack=24]="directional_attack",d[d.current_skill_group=25]="current_skill_group",d[d.abnormal_move_status_all=26]="abnormal_move_status_all",d[d.identity_stance=27]="identity_stance",d[d.pc_skill=28]="pc_skill",d[d.skill_effect_group_set=29]="skill_effect_group_set",d[d.npc_id=30]="npc_id",d[d.identity_element_value_less=31]="identity_element_value_less",d[d.pc_without_me=32]="pc_without_me",d[d.npc_scaled_level_equal=33]="npc_scaled_level_equal",d[d.npc_scaled_level_less=34]="npc_scaled_level_less",d[d.npc_scaled_level_greater=35]="npc_scaled_level_greater",d[d.not_skill_effect_id=36]="not_skill_effect_id",d[d.abnormal_move_not_immune=37]="abnormal_move_not_immune",d[d.apply_target_marking=38]="apply_target_marking",d[d.damage_attr=39]="damage_attr",d))(H||{});var p=(l=>(l[l.none=0]="none",l[l.berserker_normal=1]="berserker_normal",l[l.berserker_rush=2]="berserker_rush",l[l.warlord_normal=3]="warlord_normal",l[l.warlord_shield_of_battlefield=4]="warlord_shield_of_battlefield",l[l.destroyer_normal=5]="destroyer_normal",l[l.destroyer_focus=6]="destroyer_focus",l[l.destroyer_release=7]="destroyer_release",l[l.battle_master_normal=8]="battle_master_normal",l[l.battle_master_bubble=9]="battle_master_bubble",l[l.infighter_normal=10]="infighter_normal",l[l.infighter_vigor=11]="infighter_vigor",l[l.infighter_shock=12]="infighter_shock",l[l.forcemaster_normal=13]="forcemaster_normal",l[l.forcemaster_soul=14]="forcemaster_soul",l[l.lance_master_normal=15]="lance_master_normal",l[l.lance_master_wild=16]="lance_master_wild",l[l.lance_master_focus=17]="lance_master_focus",l[l.devil_hunter_normal=18]="devil_hunter_normal",l[l.devil_hunter_pistol=19]="devil_hunter_pistol",l[l.devil_hunter_shotgun=20]="devil_hunter_shotgun",l[l.devil_hunter_rifle=21]="devil_hunter_rifle",l[l.blaster_normal=22]="blaster_normal",l[l.blaster_cannon=23]="blaster_cannon",l[l.hawkeye_normal=24]="hawkeye_normal",l[l.hawkeye_summon=25]="hawkeye_summon",l[l.summoner_normal=26]="summoner_normal",l[l.summoner_ancient=27]="summoner_ancient",l[l.arcana_normal=28]="arcana_normal",l[l.arcana_stack=29]="arcana_stack",l[l.arcana_ruin=30]="arcana_ruin",l[l.arcana_card=31]="arcana_card",l[l.bard_normal=32]="bard_normal",l[l.bard_serenade=33]="bard_serenade",l[l.blade_burst=34]="blade_burst",l[l.holyknight_normal=35]="holyknight_normal",l[l.holyknight_holy=36]="holyknight_holy",l[l.holyknight_retribution=37]="holyknight_retribution",l[l.demonic_normal=38]="demonic_normal",l[l.demonic_capture=39]="demonic_capture",l[l.demonic_demon=40]="demonic_demon",l[l.warlord_lance=41]="warlord_lance",l[l.reaper_normal=42]="reaper_normal",l[l.reaper_dagger=43]="reaper_dagger",l[l.reaper_shadow=44]="reaper_shadow",l[l.reaper_swoop=45]="reaper_swoop",l[l.scouter_scout=46]="scouter_scout",l[l.scouter_drone=47]="scouter_drone",l[l.scouter_hyper_sync=48]="scouter_hyper_sync",l[l.scouter_fusion=49]="scouter_fusion",l[l.blade_normal=50]="blade_normal",l[l.elemental_master_normal=51]="elemental_master_normal",l[l.elemental_master_fire=52]="elemental_master_fire",l[l.elemental_master_electricity=53]="elemental_master_electricity",l[l.elemental_master_ice=54]="elemental_master_ice",l[l.yinyangshi_normal=55]="yinyangshi_normal",l[l.yinyangshi_yin=56]="yinyangshi_yin",l[l.yinyangshi_yang=57]="yinyangshi_yang",l[l.weather_artist_weapon=58]="weather_artist_weapon",l[l.weather_artist_weather=59]="weather_artist_weather",l[l.summoner_summon=60]="summoner_summon",l))(p||{});var N=(b=>(b[b.none=0]="none",b[b.underling=1]="underling",b[b.normal=2]="normal",b[b.elite=3]="elite",b[b.named=4]="named",b[b.seed=5]="seed",b[b.boss=6]="boss",b[b.raid=7]="raid",b[b.lucky=8]="lucky",b[b.epic_raid=9]="epic_raid",b[b.commander=10]="commander",b))(N||{});var J=(_=>(_[_.none=0]="none",_[_.hp=1]="hp",_[_.mp=2]="mp",_[_.str=3]="str",_[_.agi=4]="agi",_[_.int=5]="int",_[_.con=6]="con",_[_.str_x=7]="str_x",_[_.agi_x=8]="agi_x",_[_.int_x=9]="int_x",_[_.con_x=10]="con_x",_[_.criticalhit=15]="criticalhit",_[_.specialty=16]="specialty",_[_.oppression=17]="oppression",_[_.rapidity=18]="rapidity",_[_.endurance=19]="endurance",_[_.mastery=20]="mastery",_[_.criticalhit_x=21]="criticalhit_x",_[_.specialty_x=22]="specialty_x",_[_.oppression_x=23]="oppression_x",_[_.rapidity_x=24]="rapidity_x",_[_.endurance_x=25]="endurance_x",_[_.mastery_x=26]="mastery_x",_[_.max_hp=27]="max_hp",_[_.max_mp=28]="max_mp",_[_.max_hp_x=29]="max_hp_x",_[_.max_mp_x=30]="max_mp_x",_[_.max_hp_x_x=31]="max_hp_x_x",_[_.max_mp_x_x=32]="max_mp_x_x",_[_.normal_hp_recovery=33]="normal_hp_recovery",_[_.combat_hp_recovery=34]="combat_hp_recovery",_[_.normal_hp_recovery_rate=35]="normal_hp_recovery_rate",_[_.combat_hp_recovery_rate=36]="combat_hp_recovery_rate",_[_.normal_mp_recovery=37]="normal_mp_recovery",_[_.combat_mp_recovery=38]="combat_mp_recovery",_[_.normal_mp_recovery_rate=39]="normal_mp_recovery_rate",_[_.combat_mp_recovery_rate=40]="combat_mp_recovery_rate",_[_.self_recovery_rate=41]="self_recovery_rate",_[_.drain_hp_dam_rate=42]="drain_hp_dam_rate",_[_.drain_mp_dam_rate=43]="drain_mp_dam_rate",_[_.dam_reflection_rate=44]="dam_reflection_rate",_[_.char_attack_dam=47]="char_attack_dam",_[_.skill_effect_dam_addend=48]="skill_effect_dam_addend",_[_.attack_power_rate=49]="attack_power_rate",_[_.skill_damage_rate=50]="skill_damage_rate",_[_.attack_power_rate_x=51]="attack_power_rate_x",_[_.skill_damage_rate_x=52]="skill_damage_rate_x",_[_.cooldown_reduction=53]="cooldown_reduction",_[_.paralyzation_point_rate=54]="paralyzation_point_rate",_[_.def=55]="def",_[_.res=56]="res",_[_.def_x=57]="def_x",_[_.res_x=58]="res_x",_[_.def_x_x=59]="def_x_x",_[_.res_x_x=60]="res_x_x",_[_.def_pen_rate=67]="def_pen_rate",_[_.res_pen_rate=68]="res_pen_rate",_[_.physical_inc_rate=69]="physical_inc_rate",_[_.magical_inc_rate=70]="magical_inc_rate",_[_.self_shield_rate=71]="self_shield_rate",_[_.hit_rate=72]="hit_rate",_[_.dodge_rate=73]="dodge_rate",_[_.critical_hit_rate=74]="critical_hit_rate",_[_.critical_res_rate=75]="critical_res_rate",_[_.critical_dam_rate=76]="critical_dam_rate",_[_.attack_speed=77]="attack_speed",_[_.attack_speed_rate=78]="attack_speed_rate",_[_.move_speed=79]="move_speed",_[_.move_speed_rate=80]="move_speed_rate",_[_.prop_move_speed=81]="prop_move_speed",_[_.prop_move_speed_rate=82]="prop_move_speed_rate",_[_.vehicle_move_speed=83]="vehicle_move_speed",_[_.vehicle_move_speed_rate=84]="vehicle_move_speed_rate",_[_.ship_move_speed=85]="ship_move_speed",_[_.ship_move_speed_rate=86]="ship_move_speed_rate",_[_.fire_dam_rate=87]="fire_dam_rate",_[_.ice_dam_rate=88]="ice_dam_rate",_[_.electricity_dam_rate=89]="electricity_dam_rate",_[_.earth_dam_rate=91]="earth_dam_rate",_[_.dark_dam_rate=92]="dark_dam_rate",_[_.holy_dam_rate=93]="holy_dam_rate",_[_.elements_dam_rate=94]="elements_dam_rate",_[_.fire_res_rate=95]="fire_res_rate",_[_.ice_res_rate=96]="ice_res_rate",_[_.electricity_res_rate=97]="electricity_res_rate",_[_.earth_res_rate=99]="earth_res_rate",_[_.dark_res_rate=100]="dark_res_rate",_[_.holy_res_rate=101]="holy_res_rate",_[_.elements_res_rate=102]="elements_res_rate",_[_.self_cc_time_rate=105]="self_cc_time_rate",_[_.enemy_cc_time_rate=106]="enemy_cc_time_rate",_[_.identity_value1=107]="identity_value1",_[_.identity_value2=108]="identity_value2",_[_.identity_value3=109]="identity_value3",_[_.awakening_dam_rate=110]="awakening_dam_rate",_[_.item_drop_rate=111]="item_drop_rate",_[_.gold_rate=112]="gold_rate",_[_.exp_rate=113]="exp_rate",_[_.attack_power_addend=123]="attack_power_addend",_[_.attack_power_addend_2=124]="attack_power_addend_2",_[_.npc_species_humanoid_dam_rate=125]="npc_species_humanoid_dam_rate",_[_.npc_species_devil_dam_rate=126]="npc_species_devil_dam_rate",_[_.npc_species_substance_dam_rate=127]="npc_species_substance_dam_rate",_[_.npc_species_undead_dam_rate=128]="npc_species_undead_dam_rate",_[_.npc_species_plant_dam_rate=129]="npc_species_plant_dam_rate",_[_.npc_species_insect_dam_rate=130]="npc_species_insect_dam_rate",_[_.npc_species_spirit_dam_rate=131]="npc_species_spirit_dam_rate",_[_.npc_species_wild_beast_dam_rate=132]="npc_species_wild_beast_dam_rate",_[_.npc_species_mechanic_dam_rate=133]="npc_species_mechanic_dam_rate",_[_.npc_species_ancient_dam_rate=134]="npc_species_ancient_dam_rate",_[_.npc_species_god_dam_rate=135]="npc_species_god_dam_rate",_[_.npc_species_archfiend_dam_rate=136]="npc_species_archfiend_dam_rate",_[_.vitality=137]="vitality",_[_.ship_booter_speed=138]="ship_booter_speed",_[_.ship_wreck_speed_rate=139]="ship_wreck_speed_rate",_[_.island_speed_rate=140]="island_speed_rate",_[_.attack_power_sub_rate_1=141]="attack_power_sub_rate_1",_[_.attack_power_sub_rate_2=142]="attack_power_sub_rate_2",_[_.physical_inc_sub_rate_1=143]="physical_inc_sub_rate_1",_[_.physical_inc_sub_rate_2=144]="physical_inc_sub_rate_2",_[_.magical_inc_sub_rate_1=145]="magical_inc_sub_rate_1",_[_.magical_inc_sub_rate_2=146]="magical_inc_sub_rate_2",_[_.skill_damage_sub_rate_1=147]="skill_damage_sub_rate_1",_[_.skill_damage_sub_rate_2=148]="skill_damage_sub_rate_2",_[_.resource_recovery_rate=149]="resource_recovery_rate",_[_.weapon_dam=151]="weapon_dam",_))(J||{});var Z=require("tiny-typed-emitter");var k,L,c,j,z,C,f,Y=class extends Z.TypedEmitter{constructor(n,a,h=!0,s=!!process.env.DEV){super();R(this,j);R(this,C);M(this,"PartyStatusEffectRegistry");M(this,"LocalStatusEffectRegistry");R(this,k,void 0);R(this,L,void 0);R(this,c,void 0);M(this,"debug");M(this,"trace",!1);this.PartyStatusEffectRegistry=new Map,this.LocalStatusEffectRegistry=new Map,this.debug=s,A(this,k,n),A(this,L,a),A(this,c,h)}getStatusEffectRegistryForPlayer(n,a){let h=this.getPlayerRegistry(a),s=h.get(n);if(s)return s;let e=new Map;return h.set(n,e),e}hasStatusEffectRegistryForPlayer(n,a){return this.getPlayerRegistry(a).has(n)}getPlayerRegistry(n){switch(n){case 1:return this.LocalStatusEffectRegistry;case 0:return this.PartyStatusEffectRegistry;default:break}return this.LocalStatusEffectRegistry}RemoveLocalObject(n,a){let h=this.LocalStatusEffectRegistry.get(n);if(h)for(let[,s]of h)this.RemoveStatusEffect(n,s.instanceId,1,void 0,a);this.LocalStatusEffectRegistry.delete(n)}RemovePartyObject(n,a){let h=this.PartyStatusEffectRegistry.get(n);if(h)for(let[,s]of h)this.RemoveStatusEffect(n,s.instanceId,0,void 0,a);this.PartyStatusEffectRegistry.delete(n)}RegisterStatusEffect(n){let a=this.getStatusEffectRegistryForPlayer(n.targetId,n.type),h=a.get(n.instanceId);h?w(this,c)&&h.expirationTimer&&(clearTimeout(h.expirationTimer),h.expirationTimer=void 0):n.effectType===0&&this.emit("shieldApplied",n),a.set(n.instanceId,n),this.SetupStatusEffectTimeout(n)}HasAnyStatusEffect(n,a,h,s){if(!this.hasStatusEffectRegistryForPlayer(n,a))return!1;let e=this.getStatusEffectRegistryForPlayer(n,a);for(let[,o]of e)if(!(!w(this,c)&&!this.IsReplayStatusEffectValidElseRemove(o,s))){for(let i of h)if(i===o.statusEffectId)return!0}return!1}IsReplayStatusEffectValidElseRemove(n,a){return n.expireAt===void 0||n.expireAt.getTime()>a.getTime()?!0:(this.ExpireStatusEffectByTimeout(n),!1)}HasAnyStatusEffectFromParty(n,a,h,s,e){if(!this.hasStatusEffectRegistryForPlayer(n,a))return!1;let o=this.getStatusEffectRegistryForPlayer(n,a);for(let[,i]of o)if(!(!w(this,c)&&!this.IsReplayStatusEffectValidElseRemove(i,e))&&s.includes(i.statusEffectId)&&(this.ValidForWholeRaid(i)||w(this,k).getPartyIdFromEntityId(i.sourceId)===h))return!0;return!1}RemoveStatusEffect(n,a,h,s,e){if(!this.hasStatusEffectRegistryForPlayer(n,h))return;let o=this.getStatusEffectRegistryForPlayer(n,h),i=o.get(a);i&&(w(this,c)&&(clearTimeout(i.expirationTimer),i.expirationTimer=void 0),o.delete(a),s===4&&(w(this,c)||this.IsReplayStatusEffectValidElseRemove(i,e))&&this.RegisterValueUpdate(i,i.value,0))}GetStatusEffects(n,a,h){if(!this.hasStatusEffectRegistryForPlayer(n,a))return[];let s=this.getStatusEffectRegistryForPlayer(n,a);if(!w(this,c))for(let[,e]of s)this.IsReplayStatusEffectValidElseRemove(e,h);return[...s.values()]}GetStatusEffectsFromParty(n,a,h,s){if(!this.hasStatusEffectRegistryForPlayer(n,a))return[];let e=this.getStatusEffectRegistryForPlayer(n,a);if(!w(this,c))for(let[,o]of e)this.IsReplayStatusEffectValidElseRemove(o,s);return[...e.values()].filter(o=>this.ValidForWholeRaid(o)?!0:h===w(this,k).getPartyIdFromEntityId(o.sourceId))}Clear(n){let a=0;for(let[,s]of this.LocalStatusEffectRegistry){for(let[,e]of s)this.RemoveStatusEffect(e.targetId,e.instanceId,e.type,void 0,n);a+=s.size}let h=0;for(let[,s]of this.PartyStatusEffectRegistry){for(let[,e]of s)this.RemoveStatusEffect(e.targetId,e.instanceId,e.type,void 0,n);h+=s.size}this.trace&&console.log("On Clear SE in local",a,"in party",h),this.LocalStatusEffectRegistry.clear(),this.PartyStatusEffectRegistry.clear()}UpdateDuration(n,a,h,s){let o=this.getStatusEffectRegistryForPlayer(a,s).get(n);if(o){let i=h-o.timestamp;if(w(this,c)&&o.expirationTimer&&(this.trace&&console.log("Clearing timeout for",o.instanceId,"because of duration change"),clearTimeout(o.expirationTimer),o.expirationTimer=void 0),o.expireAt){let E=o.expireAt.getTime()+Number(i),S=E-o.pktTime.getTime();S>0?(this.trace&&console.log("Extending duration by",i,"ms","New timeout delay",S,"from",o.expireAt.toISOString(),"to",new Date(E).toISOString()),w(this,c)&&(o.expirationTimer=setTimeout(this.ExpireStatusEffectByTimeout.bind(this,o),S)),o.expireAt=new Date(E),o.timestamp=h):o.expireAt=void 0}}else this.debug&&console.error("Tried to update duration for SE with instanceId",n," on target",a,"but where is no such SE registered")}SyncStatusEffect(n,a,h,s,e){let o=O(this,C,f).call(this,a,e),i=o?0:1,E=o?a:h;if(!E)return;let b=this.getStatusEffectRegistryForPlayer(E,i).get(n);if(!b)return;let T=b.value;b.value=s,this.RegisterValueUpdate(b,T,s)}ValidForWholeRaid(n){return(n.buffCategory===3||n.buffCategory===1||n.buffCategory===2)&&n.category===1&&n.showType===1}SetupStatusEffectTimeout(n){if(n.expirationDelay>0&&n.expirationDelay<604800){let a=n.pktTime.getTime()>n.occurTime.getTime()?n.pktTime:n.occurTime,h=Math.ceil(n.expirationDelay*1e3),s=a.getTime()+h+Y.TIMEOUT_DELAY_MS-n.pktTime.getTime();n.expireAt=new Date(n.pktTime.getTime()+s),this.trace&&console.log("Setting up statuseffect expiration time for",n.name,n.instanceId,"to",n.expireAt.toISOString(),"with delay",s),w(this,c)&&(n.expirationTimer=setTimeout(this.ExpireStatusEffectByTimeout.bind(this,n),s))}}ExpireStatusEffectByTimeout(n){this.debug&&console.error("Triggered timeout on",n.name,"with iid",n.instanceId),this.RemoveStatusEffect(n.targetId,n.instanceId,n.type,void 0,new Date)}RegisterValueUpdate(n,a,h){n.effectType===0&&this.emit("shieldChanged",n,a,h)}newPC(n,a,h){let s=O(this,C,f).call(this,n.pcStruct.characterId,a);s?this.RemovePartyObject(n.pcStruct.characterId,h):this.RemoveLocalObject(n.pcStruct.playerId,h);for(let e of n.pcStruct.statusEffectDatas)this.RegisterStatusEffect(this.buildStatusEffect(e,s?n.pcStruct.characterId:n.pcStruct.playerId,e.sourceId,s?0:1,h))}buildStatusEffect(n,a,h,s,e){let o=n.value?n.value.readUInt32LE():0,i=n.value?n.value.readUInt32LE(8):0,E=o<i?o:i,S=0,b=0,T=0,q="Unknown",P=1,D=w(this,L).skillBuff.get(n.statusEffectId);if(D){switch(q=D.name,D.category){case"debuff":S=1;break}switch(D.buffcategory){case"bracelet":b=1;break;case"etc":b=2;break;case"battleitem":b=3;break}switch(D.iconshowtype){case"all":T=1;break}switch(D.type){case"shield":P=0;break}}return{instanceId:n.effectInstanceId,sourceId:h,statusEffectId:n.statusEffectId,targetId:a,type:s,dbTarget:D?.target??"none",value:E,buffCategory:b,category:S,showType:T,expirationDelay:n.totalTime,expirationTimer:void 0,timestamp:n.endTick,expireAt:void 0,occurTime:n.occurTime,name:q,pktTime:e,effectType:P,stackCount:n.stackCount}}getStatusEffects(n,a,h,s){let e=[],o=[],i=O(this,j,z).call(this,n,h),E=this.GetStatusEffects(i?n.characterId:n.entityId,i?0:1,s);for(let S of E)o.push([S.statusEffectId,S.sourceId,S.stackCount]);if(a){let S=O(this,j,z).call(this,a,h),b=w(this,k).isEntityInParty(n.entityId),T=b?w(this,k).getPartyIdFromEntityId(n.entityId):void 0,q=b&&T?this.GetStatusEffectsFromParty(S?a.characterId:a.entityId,S?0:1,T,s):this.GetStatusEffects(S?a.characterId:a.entityId,S?0:1,s);for(let P of q)P.type===1&&P.category===1&&P.sourceId!==n.entityId&&P.dbTarget==="self"||e.push([P.statusEffectId,P.sourceId,P.stackCount])}return[o,e]}},W=Y;k=new WeakMap,L=new WeakMap,c=new WeakMap,j=new WeakSet,z=function(n,a){if(n.entityType!==1)return!1;let h=n;return O(this,C,f).call(this,h.characterId,a)},C=new WeakSet,f=function(n,a){let h=w(this,k).isCharacterInParty(a),s=w(this,k).isCharacterInParty(n);if(h){if(!s||n===a)return!1;let e=w(this,k).getPartyIdFromCharacterId(a),o=w(this,k).getPartyIdFromCharacterId(n);return e===o}return!1},M(W,"TIMEOUT_DELAY_MS",1e3);var K=class{dbPath="";modulePath;enums;npc;PCData;skill;skillBuff;skillEffect;skillFeature;combatEffect;esther;itemSet;constructor(r="./meter-core/data"){this.modulePath=r,this.enums=new Map,this.npc=new Map,this.PCData=new Map,this.skill=new Map,this.skillBuff=new Map,this.skillEffect=new Map,this.skillFeature=new Map,this.combatEffect=new Map,this.esther=[],this.itemSet={items:new Map,seteffects:new Map}}processEnumData(r){for(let[n,a]of Object.entries(r)){let h=new Map;for(let[s,e]of Object.entries(a))h.set(s,e);this.enums.set(n,h)}}processNpcData(r){for(let n of Object.values(r))this.npc.set(n.id,n)}processPCData(r){for(let[n,a]of Object.entries(r))this.PCData.set(parseInt(n),a)}processSkillData(r){for(let n of Object.values(r))this.skill.set(n.id,n)}processSkillBuffData(r){for(let n of Object.values(r))this.skillBuff.set(n.id,n)}processSkillBuffEffectData(r){for(let n of Object.values(r))this.skillEffect.set(n.id,n)}processSkillFeature(r){for(let n of Object.values(r)){let a=new Map;for(let h of Object.values(n.tripods))a.set(h.key,h);this.skillFeature.set(n.skillid,a)}}processCombatEffectData(r){for(let n of Object.values(r))this.combatEffect.set(n.id,n)}processEsther(r){this.esther=Object.values(r)}processItemSet(r){for(let[n,a]of Object.entries(r)){let h=new Map;for(let[s,e]of Object.entries(a)){let o=new Map;for(let[i,E]of Object.entries(e.value))o.set(parseInt(i),E);h.set(parseInt(s),o);for(let i of Object.values(e.itemids))this.itemSet.items.set(i,{setname:n,level:parseInt(s)})}this.itemSet.seteffects.set(n,h)}}getNpcName(r){return this.npc.get(r)?.name||""}getClassName(r){return this.PCData.get(r)||""}getSkillName(r){return this.skill.get(r)?.name||""}getSkillClassId(r){return this.skill.get(r)?.classid||0}getSkillEffectComment(r){return this.skillEffect.get(r)?.comment||""}getSkillEffectDirectionalMask(r){return this.skillEffect.get(r)?.directionalmask||0}getSkillEsther(r){for(let n of this.esther)if(n.skills.includes(r))return n}getNpcEsther(r){for(let n of this.esther)if(n.npcs.includes(r))return n}getStatusEffectHeaderData(r){let n=this.skillBuff.get(r);if(!n||n.iconshowtype==="none")return;let a;n.buffcategory==="ability"&&[501,502,503,504,505].includes(n.uniquegroup)?a="dropsofether":a=n.buffcategory;let h={target:n.target==="none"?0:n.target==="self"?2:1,category:n.category,buffcategory:a,bufftype:this.getStatusEffectBuffTypeFlags(n),uniquegroup:n.uniquegroup,source:{name:n.name,desc:n.desc,icon:n.icon}};if(a==="classskill"||a==="identity"){let s;if(n.sourceskill)s=this.skill.get(n.sourceskill),s&&(h.source.skill=s);else{let e=Math.floor(r/100)*10;if(s=this.skill.get(e),!s){let o=Math.floor(n.uniquegroup/100)*10;s=this.skill.get(o)}s&&(h.source.skill=s)}s&&(h.source.skill=s)}else if(a==="ability"&&n.uniquegroup!==0){let s;if(n.sourceskill)s=this.skill.get(n.sourceskill),s&&(h.source.skill=s);else{let e=Math.floor(r/100)*10;if(s=this.skill.get(e),!s){let o=Math.floor(n.uniquegroup/100)*10;s=this.skill.get(o)}}s&&(h.source.skill=s)}else a==="set"&&n.setname&&(h.source.setname=n.setname);return h}getStatusEffectBuffTypeFlags(r){let n=0;return["weaken_defense","weaken_resistance","skill_damage_amplify","beattacked_damage_amplify","skill_damage_amplify_attack","directional_attack_amplify","instant_stat_amplify","attack_power_amplify","instant_stat_amplify_by_contents"].includes(r.type)?n|=1:["move_speed_down","all_speed_down"].includes(r.type)?n|=8:["reset_cooldown"].includes(r.type)?n|=128:["change_ai_point","ai_point_amplify"].includes(r.type)?n|=256:["increase_identity_gauge"].includes(r.type)&&(n|=64),r.passiveoption.forEach(a=>{let h=V[a.type];if(a.type==="stat"){let s=J[a.keystat];[20,26,54].includes(s)&&(n|=256),[18,24,53].includes(s)&&(n|=128),[28,30,32,37,38,39,40,149].includes(s)&&(n|=64),[6,10,27,29,31,33,34,35,36,41,42,137].includes(s)&&(n|=16),(55<=s&&s<=70||[19,25].includes(s))&&(r.category==="buff"&&a.value>=0||r.category==="debuff"&&a.value<=0?n|=1:n|=32),79<=s&&s<=84&&(n|=8),[77,78,18,24].includes(s)&&(n|=4),[74,15,21].includes(s)&&(n|=2),(141<=s&&s<=148||87<=s&&s<=94||[3,4,5,7,8,9,47,49,50,51,52,72,73,76,110,123,151].includes(s))&&(r.category==="buff"&&a.value>=0||r.category==="debuff"&&a.value<=0?n|=1:n|=32)}else if(6===h)n|=2;else if([5,29,34,7,8].includes(h))r.category==="buff"&&a.value>=0||r.category==="debuff"&&a.value<=0?n|=1:n|=32;else if([27,35].includes(h))n|=128;else if([26,25].includes(h))n|=64;else if(4===h){let s=this.combatEffect.get(a.keyindex);if(!s)return;s.effects.forEach(e=>{e.actions.forEach(o=>{let i=G[o.type];[1,2,4,5,6,19,20,16].includes(i)?n|=1:3===i&&(n|=2)})})}}),n}getStatPairMap(r){let n=new Map;return r.forEach(a=>{n.set(a.statType,a.value)}),n}isCombatEffectConditionsValid({effect:r,self:n,target:a,caster:h,skill:s,hitOption:e,targetCount:o}){let i=!0;return r.conditions.forEach(E=>{if(!i)return;let S=U[E.actor];switch(H[E.type]){case 21:(!o||o!==E.arg)&&(i=!1);break;case 1:(!s||s.id===E.arg)&&(i=!1);break;case 16:S===1?(!n||n.entityType!==1)&&(i=!1):S===2?(!a||a.entityType!==1)&&(i=!1):S===3?(!h||h.entityType!==1)&&(i=!1):i=!1;break;case 22:(!s||!s.identitycategory||p[s.identitycategory]!=E.arg)&&(i=!1);break;case 13:(!a||![2,3].includes(a.entityType)||!a.pushimmune)&&(i=!1);break;case 15:i=!1;break;case 11:i=!1;break;case 12:i=!1;break;case 25:(!s||!s.groups||!s.groups.includes(E.arg))&&(i=!1);break;case 2:if(S===1)(!n||Number((n.stats.get(1)??0n)/(n.stats.get(27)??0n))>=E.arg/100)&&(i=!1);else if(S===2)(!a||Number((a.stats.get(1)??0n)/(a.stats.get(27)??0n))>=E.arg/100)&&(i=!1);else if(S===3)(!h||Number((h.stats.get(1)??0n)/(h.stats.get(27)??0n))>=E.arg/100)&&(i=!1);else{i=!1;break}break;case 34:S===2&&a&&[2,3].includes(a.entityType)?a.balanceLevel>E.arg&&(i=!1):i=!1;break;case 6:if(S===2)if(a&&[2,3].includes(a.entityType)){let b=N[a.grade];(!b||b>E.arg)&&(i=!1)}else i=!1;else i=!1;break;case 7:if(S===2)if(a&&[2,3].includes(a.entityType)){let b=N[a.grade];(!b||b<E.arg)&&(i=!1)}else i=!1;else i=!1;break;case 27:S===1?(!n||n.entityType!==1||n.stance!==E.arg)&&(i=!1):i=!1;break;case 24:(!e||!(e+1&E.arg))&&(i=!1);break;default:i=!1;break}}),i}isSupportClassId(r){return r===105||r===204||r===602}isBattleItem(r,n){let a=this.skillEffect.get(r)?.itemcategory;switch(n){case"attack":return a==="useup_battle_item_common_attack";case"buff":return a==="useup_battle_item_common_buff";case"function":return a==="useup_battle_item_common_function";default:return typeof a=="string"}}getBattleItemName(r){return this.skillEffect.get(r)?.itemname||""}loadDbs(r){this.dbPath=r,this.processEnumData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"Enums.json"),"utf-8"))),this.processNpcData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"Npc.json"),"utf-8"))),this.processPCData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"PCData.json"),"utf-8"))),this.processSkillData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"Skill.json"),"utf-8"))),this.processSkillBuffData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"SkillBuff.json"),"utf-8"))),this.processSkillBuffEffectData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"SkillEffect.json"),"utf-8"))),this.processSkillFeature(JSON.parse((0,I.readFileSync)((0,x.join)(r,"SkillFeature.json"),"utf-8"))),this.processCombatEffectData(JSON.parse((0,I.readFileSync)((0,x.join)(r,"CombatEffect.json"),"utf-8"))),this.processEsther(JSON.parse((0,I.readFileSync)((0,x.join)(r,"Esther.json"),"utf-8"))),this.processItemSet(JSON.parse((0,I.readFileSync)((0,x.join)(r,"ItemSet.json"),"utf-8")))}};0&&(module.exports={MeterData});
