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
  
  TP_printk("%llu\n" , __entry->reg0.smin_value)
); 

#endif
#include <trace/define_trace.h>
