import io
L=[
("0x1049db00","audio_eventset_objs_build_0x324","audio","walks mgr(+0x68)+0xc0->+0xac/+0xb0 lists to +0xec leaves; allocs 0x324-byte eventset obj each; callee audio_eventset_ctor family"),
("0x1049f3c0","core_rec54_array_grow_copy","core","capacity doubling (*2 while < need) + realloc of 0x54-stride records; copies field blocks from -0x30/-0x20 offsets"),
("0x1049600d","anim_hashflag_state_check","anim","tail-cont style; compares hashed ids 0xd52518f5/0x1ffcc77/-0x63f996f3; sets flag *(this+0xd8)+0xf+idx*0x10; FUN_10491040/FUN_104c9970"),
("0x104806d0","anim_fade_frame_select_switch","anim","fade=(t-vtbl+0x30)*scale ROUND&0xfff; double-buffer pick FUN_102964f0((n+1+(fade>>12)&1)*7+10); switch over floats +0x60..+0x74; mat compose"),
("0x10497ff0","entry_dist_gate_halfext_calc","unknown","entries gated byte+0x54 and dist +0xc/+0x10<param_3; marks seen bytes this+0x130; corner box half-extent calc via 0.5/range scale"),
("0x1049d630","audio_unit_eventsets_bind_channels","audio","same mgr-list walk as 1049db00 but calls battle_anim_unit_audio_eventset_build x2 + channel getter 10cffc30 x2; count +0x18++, flag +0x32"),
("0x1047f980","render_box_batch_alpha_accum","render","heading LUT (short+0x4000) builds +/- half-extent boxes; accumulates DAT_11e0ad38 counter and DAT_11e034a8*255 alpha across batches"),
("0x1047c350","battle_impact_fx_emit_walk","battle","gate FUN_104dd8d0 -> FUN_10490480 emit; special case id==0x3c3 w/ 3.0/-2.0 thresholds; sums +0x50->+0xc counts; per-entry thresh byte|=1, vec copy 11354460"),
]
with io.open('funcid_solo.tsv','a',encoding='utf-8',newline='\n') as f:
    for a,n,s,e in L: f.write('%s\t%s\t%s\t%s\n'%(a,n,s,e))
print('appended',len(L))
