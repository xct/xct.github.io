---
categories:
- Fuzzing
layout: post
media_subpath: /assets/posts/2018-05-17-dynamic-binary-instrumentation-with-dynamorio
tags:
- fuzzing
title: Dynamic Binary Instrumentation with DynamoRIO
---

DynamoRIO (<https://dynamorio.org/>) is a dynamic binary instrumentation framework that allows to manipulate binary code at runtime. The framework can be used to build various tools for program analysis, profiling, optimization and many more on top of it.

The basic principle of DynamoRIO is to put all code that is to be executed into a code cache, while allowing the user to manipulate the contents of said code cache. To do so one needs to write a *client*. Clients are pieces of software that use the DynamoRIO API to achieve various goals. To interact with clients DynamoRIO exposes a series of events to which one can register to. For example the *dr\_register\_bb\_event* gets called every time a basic block is put into the code cache. This happens just once per basic block regardless of the number of execution of that block.

In this post I will show how to use DynamoRIO to build a simple basic block tracer for binaries. We start by creating a main method:

```
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]){
    drmgr_init();
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
```

What this does is to initialize *drmgr*, the DynamoRIO multi-instrumentation manager, and register to two events. The first event is the exit event which is called when the program exits. We use this to print the trace to stdout when the program finishes. The *bb\_instrumentation\_event* is called every time a new basic block is put into the code cache. We will use this event to insert code into every basic block that saves the address of said basic block upon execution. Now we continue by writing *the event\_app\_instruction* function which we just hooked to the basic block caching mechanism.

```
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, bool translating, void *user_data){   
    if (!drmgr_is_first_instr(drcontext, inst)){
        return DR_EMIT_DEFAULT;
    }  
    dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *)trace_bb, false, 1, OPND_CREATE_INTPTR(tag)); 
    return DR_EMIT_DEFAULT;
}
```

Whenever a basic block is put into cache we insert a new call to the function *trace\_bb* into it. The function takes exactly one argument which is defined by *OPND\_CREATE\_INTPTR(tag)*. This argument is the address of the first instruction of the basic block. The actual *trace\_bb* function which is then called upon execution of every basic block is as follows.

```
static void trace_bb(void* tag) { 
    trace[i++] = tag;  
}
```

The simple function takes the address of the basic block and puts it into a static variable which is printed out in the exit function we registered earlier.

```
static void event_exit(void) {
  for(int j=0;j<i;j++){
    dr_printf("%d %p\n", j, trace[j]);       
  }
  drmgr_exit();
}
```

With these few functions we can get an accurate trace of a target binary. There are more examples in the excellent DynamoRIO documentation at [https://dynamorio.org/docs/API\_samples.html](https://dynamorio.org/docs/API_samples.html).