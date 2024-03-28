#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_state

#if !defined(_TRACE_BPF_STATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_STATE_H

#include <linux/tracepoint.h>

TRACE_EVENT(bpf_state,

  TP_PROTO(
    unsigned long long value,
    unsigned long long mask,
    signed long long smin,
    signed long long smax,
    unsigned long long umin,
    unsigned long long umax,
    signed int s32_min,
    signed int s32_max,
    unsigned int u32_min,
    unsigned int u32_max
  ),
  
  TP_ARGS(value, mask, smin, smax, umin, umax, s32_min, s32_max, u32_min, u32_max),
  
  TP_STRUCT__entry(
    __field(unsigned long long, value)
    __field(unsigned long long, mask)
    __field(signed long long, smin)
    __field(signed long long, smax)
    __field(unsigned long long, umin)
    __field(unsigned long long, umax)
    __field(signed int, s32_min)
    __field(signed int, s32_max)
    __field(unsigned int, u32_min)
    __field(unsigned int, u32_max)
  ),
  
  TP_fast_assign(
      __entry->value = value;
      __entry->mask = mask;
      __entry->smin = smin;
      __entry->smax = smax;
      __entry->umin = umin;
      __entry->umax = umax;
      __entry->s32_min = s32_min;
      __entry->s32_max = s32_max;
      __entry->u32_min = u32_min;
      __entry->u32_max = u32_max;
  ), 
  
  TP_printk("OUPUT\nvalue: %llu\nmask: %llu\ns64_min: %lld\ns64_max: %lld\n" \
            "u64_min: %lluu64_max: %llu\ns32_min: %d\ns32_max: %d\n" \
            "u32_min: %u\nu32_max: %u\n",
            __entry->value, __entry->mask, __entry->smin, __entry->smax, 
            __entry->umin, __entry->umax, __entry->s32_min, __entry->s32_max, 
            __entry->u32_min, __entry->u32_max
  )
); 

#endif
#include <trace/define_trace.h>
