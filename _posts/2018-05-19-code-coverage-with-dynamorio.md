---
categories:
- Fuzzing
layout: post
media_subpath: /assets/posts/2018-05-19-code-coverage-with-dynamorio
tags:
- fuzzing
title: Code coverage with DynamoRIO
---

DynamoRIO comes with a handy tool to generate code coverage data for any program. To generate the data we need to use *drrun* with the *drcov* client. For this post we will generate coverage data for a simple example program. When choosing a target program it’s best to have the source code available and to compile it with debug symbols. Drcov also works without source code, but in that case the results will miss some features like line coverage.

As a running example we will use [this](https://github.com/xct/challenges/blob/master/src/002.c) simple program. It basically contains a function that parses some file input. Depending on the contents of the file different code paths will be executed. We generate two sample input files with python -c ‘print "X" \* 100’ and python -c ‘print "Y" \* 100’ and place them in a separate *inputs* folder in the working directory. When having multiple inputs drcov will generate coverage data for every input file which can later be aggregated into a single report.

```
for i in `ls -1 inputs/`; do drrun -t drcov -- challenges/build64/002 inputs/$i; done
```

At this point drcov has created two \*.log files, which are binary files that contain the coverage data. To make these human readable we convert them via *drcov2lcov* into the lcov format. At this point it is helpfull to apply a so called *src\_filter*, which only converts parts over to lcov that match the filter. In this way it can be avoided to generate coverage for standard libraries and other uninteresting parts of the program. For this example create a *src* folder in the working directory and copy over the sample programs source.  
Now we can convert into the lcov format with the source filter set.

```
drcov2lcov -dir . -output coverage.info -src_filter 002
```

Now that we have obtained the coverage data in lcov format, a html report can be generated using:

```
genhtml coverage.info --output-directory out
```

When finished the line coverage percentage of the given inputs is printed out. In this case it shows 79.3% (23 of 29 lines). Inside the *out* directory the html report is generated which looks like this:

![](howto_dynamorio_cov.png)

In the source view we can see wich parts have been reached by the given inputs, highlighted in blue. The parts that have not been reached are highlighted in orange. Drcov is a useful tool to evaluate fuzzers and other programs that want too optimize towards reaching large code coverage.