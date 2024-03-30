#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_state
#if !defined(_TRACE_BPF_STATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_STATE_H

#include <linux/tracepoint.h>
#include <linux/bpf_verifier.h>

TRACE_EVENT(bpf_state,

  TP_PROTO(
    struct bpf_reg_state *regs
  ),
  
  TP_ARGS(regs),
  
  TP_STRUCT__entry(
    __field_struct(struct bpf_reg_state, reg0)
    __field_struct(struct bpf_reg_state, reg1)
    __field_struct(struct bpf_reg_state, reg2)
    __field_struct(struct bpf_reg_state, reg3)
    __field_struct(struct bpf_reg_state, reg4)
    __field_struct(struct bpf_reg_state, reg5)
    __field_struct(struct bpf_reg_state, reg6)
    __field_struct(struct bpf_reg_state, reg7)
    __field_struct(struct bpf_reg_state, reg8)
    __field_struct(struct bpf_reg_state, reg9)
  ),
  
  TP_fast_assign(
      __entry->reg0 = regs[0];
      __entry->reg1 = regs[1];
      __entry->reg2 = regs[2];
      __entry->reg3 = regs[3];
      __entry->reg4 = regs[4];
      __entry->reg5 = regs[5];
      __entry->reg6 = regs[6];
      __entry->reg7 = regs[7];
      __entry->reg8 = regs[8];
      __entry->reg9 = regs[9];
  ), 
  
  TP_printk(
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u " \
          "%llu %llu %llu %llu %llu %llu %u %u %u %u",
          __entry->reg0.var_off.value, __entry->reg0.var_off.mask,
          __entry->reg0.smin_value, __entry->reg0.smax_value,
          __entry->reg0.umin_value, __entry->reg0.umax_value,
          __entry->reg0.s32_min_value, __entry->reg0.s32_max_value,
          __entry->reg0.u32_min_value, __entry->reg0.u32_max_value,
          __entry->reg1.var_off.value, __entry->reg1.var_off.mask,
          __entry->reg1.smin_value, __entry->reg1.smax_value,
          __entry->reg1.umin_value, __entry->reg1.umax_value,
          __entry->reg1.s32_min_value, __entry->reg1.s32_max_value,
          __entry->reg1.u32_min_value, __entry->reg1.u32_max_value,
          __entry->reg2.var_off.value, __entry->reg2.var_off.mask,
          __entry->reg2.smin_value, __entry->reg2.smax_value,
          __entry->reg2.umin_value, __entry->reg2.umax_value,
          __entry->reg2.s32_min_value, __entry->reg2.s32_max_value,
          __entry->reg2.u32_min_value, __entry->reg2.u32_max_value,
          __entry->reg3.var_off.value, __entry->reg3.var_off.mask,
          __entry->reg3.smin_value, __entry->reg3.smax_value,
          __entry->reg3.umin_value, __entry->reg3.umax_value,
          __entry->reg3.s32_min_value, __entry->reg3.s32_max_value,
          __entry->reg3.u32_min_value, __entry->reg3.u32_max_value,
          __entry->reg4.var_off.value, __entry->reg4.var_off.mask,
          __entry->reg4.smin_value, __entry->reg4.smax_value,
          __entry->reg4.umin_value, __entry->reg4.umax_value,
          __entry->reg4.s32_min_value, __entry->reg4.s32_max_value,
          __entry->reg4.u32_min_value, __entry->reg4.u32_max_value,
          __entry->reg5.var_off.value, __entry->reg5.var_off.mask,
          __entry->reg5.smin_value, __entry->reg5.smax_value,
          __entry->reg5.umin_value, __entry->reg5.umax_value,
          __entry->reg5.s32_min_value, __entry->reg5.s32_max_value,
          __entry->reg5.u32_min_value, __entry->reg5.u32_max_value,
          __entry->reg6.var_off.value, __entry->reg6.var_off.mask,
          __entry->reg6.smin_value, __entry->reg6.smax_value,
          __entry->reg6.umin_value, __entry->reg6.umax_value,
          __entry->reg6.s32_min_value, __entry->reg6.s32_max_value,
          __entry->reg6.u32_min_value, __entry->reg6.u32_max_value,
          __entry->reg7.var_off.value, __entry->reg7.var_off.mask,
          __entry->reg7.smin_value, __entry->reg7.smax_value,
          __entry->reg7.umin_value, __entry->reg7.umax_value,
          __entry->reg7.s32_min_value, __entry->reg7.s32_max_value,
          __entry->reg7.u32_min_value, __entry->reg7.u32_max_value,
          __entry->reg8.var_off.value, __entry->reg8.var_off.mask,
          __entry->reg8.smin_value, __entry->reg8.smax_value,
          __entry->reg8.umin_value, __entry->reg8.umax_value,
          __entry->reg8.s32_min_value, __entry->reg8.s32_max_value,
          __entry->reg8.u32_min_value, __entry->reg8.u32_max_value,
          __entry->reg9.var_off.value, __entry->reg9.var_off.mask,
          __entry->reg9.smin_value, __entry->reg9.smax_value,
          __entry->reg9.umin_value, __entry->reg9.umax_value,
          __entry->reg9.s32_min_value, __entry->reg9.s32_max_value,
          __entry->reg9.u32_min_value, __entry->reg9.u32_max_value
          )
); 

#endif
#include <trace/define_trace.h>
