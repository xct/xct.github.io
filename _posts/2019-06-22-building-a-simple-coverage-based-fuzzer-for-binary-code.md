---
categories:
- Fuzzing
layout: post
media_subpath: /assets/posts/2019-06-22-building-a-simple-coverage-based-fuzzer-for-binary-code
tags:
- dynamorio
title: Building a simple coverage based fuzzer for binary code
---

In this post I will walk through the process of creating a simple coverage based fuzzer. The code of this project is on available [here](https://github.com/xct/simple_fuzzer). The general idea here is that you download the code and read this post to understand what it does on the more interesting parts so you are able to extend it or write your own fuzzer based on the concepts.

On a high level view the fuzzer takes one or more seed files, traces the program execution with the seeds as inputs and builds up a map of all paths seen within the program. It then generates new inputs that will be traced as well. If any of these new inputs generates coverage that has not been seen before it is added to the queue. Files in queue are combined and mutated to generate new inputs for the next round of fuzzing. This process is continued and aimed towards optimizing coverage.

For obtaining the necessary code coverage for our fuzzer many methods exist. The goal is to record (trace) which basic blocks are executed when the target program runs. [AFL](http://lcamtuf.coredump.cx/afl/) for example uses a custom version of qemu usermode to achieve this tracing, while [hongfuzz](https://github.com/google/honggfuzz.git) supports several more recent methods, one of them being Intel Processor Trace, a hardware tracing feature of recent Intel CPUs (>= Skylake) that allows tracing with minimal overhead. While hardware tracing certainly is the most effective method, not everyone has a Intel CPU so at this point the fuzzer will be based on software tracing.

Dynamorio is a binary instrumentation framework that allows all kinds of manipulation and information gathering of running binaries. For obtaining coverage it already contains a tool we can use named `drcov`.

To get started get and build dynamorio:

```
git clone https://github.com/DynamoRIO/dynamorio.git
cd dynamorio && mkdir build64 && cd build64
cmake ..
make -j32
```

Obtaining coverage is fairly simple – you start `drrun` with `drcov` and tell it which binary to run:

```
~/dynamorio/build64/bin64/drrun -t drcov -dump_text -- objdump -d /usr/bin/id
```

This creates a file named `drcov.x86_64-linux-gnu-objdump.18410.0000.proc.log` with the following contents:

```
...
  4,   4, 0x00007f1477464000, 0x00007f147746b000, 0x00007f147746c2b0, 0000000000000000,  /usr/bin/x86_64-linux-gnu-objdump
  5,   4, 0x00007f147746b000, 0x00007f14774a0000, 0x00007f147746c2b0, 0000000000007000,  /usr/bin/x86_64-linux-gnu-objdump
  6,   4, 0x00007f14774a0000, 0x00007f14774b6000, 0x00007f147746c2b0, 000000000003c000,  /usr/bin/x86_64-linux-gnu-objdump
  7,   4, 0x00007f14774b7000, 0x00007f14774be000, 0x00007f147746c2b0, 00000000000523d0,  /usr/bin/x86_64-linux-gnu-objdump
  8,   8, 0x00007f147b494000, 0x00007f147b495000, 0x00007f147b495090, 0000000000000000,  /usr/lib/x86_64-linux-gnu/ld-2.28.so
  9,   8, 0x00007f147b495000, 0x00007f147b4b3000, 0x00007f147b495090, 
...
module[  9]: 0x0000000000001090,   8
module[  9]: 0x0000000000001e90,  85
module[  9]: 0x0000000000001ee5,  64
module[  9]: 0x0000000000001f43,   6
module[  9]: 0x0000000000001f33,  16
...
```

At the top you can see a list of loaded modules, showing an index, at which addresses they are loaded and their name. After the module section we see the actual basic blocks that have been executed with their addresses, relative to their module start. To use this in our fuzzer it is important to run the target binary via dynamorio and parse the results, which is done by the run\_and\_trace method.

```
...
cmd = [dynamorioHOME+"/bin64/drrun", "-t", "drcov", "-dump_text","--"]
        for i in target.split(" "):
            cmd.append(i)
proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
        await proc.wait()
...
```

As shown before this runs the target and generates coverage data. The output is read back and module and basic block data are parsed via regexes into lists.

Now that we have obtained coverage a widely used approach is to create a map from it that records all edges in the program. The idea here is that programs can be viewed as graphs where the nodes are basic blocks and the transition between the basic blocks are edges.

We are going to follow the approach afl is using in this post, which is xoring the from and to address of two basic blocks together on a transition. Since we want to distribute the map entries evenly we first map the addresses to unique random values:

```
def store(self, addr):
    if addr not in self.bbs:
        self.bbs[addr] = random.randint(0, 0xFFFFFFFF) 
    return self.bbs[addr]

def get(self, num):
    for k, v in self.bbs.items():
        if v == num:
            return self.bbs[k]
    assert(num in self.bbs.values())
```

Afterwards we xor them and store them in said map:

```
def update(self, addr1, addr2):
    cov = False
    addr1 = self.store(addr1)
    addr2 = self.store(addr2)
    e = addr1 ^ addr2
    if e not in self.edges:
        cov = True
        self.edges[e] = 0
        if self.verbose:
            print("    +Cov")
    else:
        self.edges[e] += 1
    return cov
```

The whole point of it is to save information about which transitions are already known so new transitions can be recognized and treated accordingly.

As we can now trace executions with any input files it is time to think about how to create input files. There a various approaches on handling this – for this post I will use a simple genetic algorithm.

We select 2 random inputs from queue and combine them into one new input. To achieve this I loop through all of inputs bytes and choose a byte from on or the other parent while creating the child. This makes sure the new input has bytes from both parents. The following code snippet shows the generate method of the genetic input generator:

```
def generate(self):
    child = b''
    # selection (choose parents)
    left = random.choice(self.samples)
    right = random.choice(self.samples)
    # crossover 
    length = random.choice([len(left),len(right)])
    for i in range(length):
        coin = random.randint(0,1)
        if coin == 0 and len(left) >= i:
            child += left[i:i+1]
        elif coin == 1 and len(right) >= i:    
            child += right[i:i+1]
        else:
            if len(left) > len(right):
                child += left[i:i+1]
            else:
                child += right[i:i+1]
    # mutate length (and fill with random bytes)
    multiplier = random.uniform(1.0, 2.0)
    length = int(length * multiplier)

    # random mutation
    mutated = b''
    for i in range(length):
        coin = random.randint(0, 100)            
        if coin < self.mutation_rate: # n % chance
            mutated += os.urandom(1)                
        else:
            mutated += child[i:i+1]            
    child = mutated
    return child
```

Compared to other coverage driven fuzzers this one is very slow because it is written in python, doesn’t optimize process loading and various other reasons. If you want to write a productive one I suggest to look into the technical details of AFL – speed is essential when fuzzing. This concludes this post – feel free to reach out for questions, ideas or feedback.