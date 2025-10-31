---
description: lz4-java development guide
author: Jonas Konrad
version: 1.0
globs: ["**/*.java", "**/*.mvel", "**/*.c", "**/*.xml"]
---

# lz4-java development guide

## Project Overview

This Maven project contains the Java implementation of the lz4 compression algorithm. There are implementations based 
on normal Java, sun.misc.Unsafe, and JNI for each API.

## Build

The project is built with Maven. Always use the maven wrapper (`./mvnw`) to build the project.

The library itself is built using Java 7. It is assumed that the development environment has a Maven toolchain for 
Java 7 already installed.

The tests compile and run with more recent versions defined in the pom.xml.

## Structure

For the JNI implementation, there is a git submodule containing the upstream lz4 library.

## Code style

Code style should be kept consistent with existing source files to keep changes to a minimum. `.editorconfig` contains 
some rules.

## Binary compatibility

- You MUST NOT break any public facing API without explicit consent
- You SHOULD reduce the visibility of members for non user-facing APIs.

## Unit testing

Unit tests are implemented using JUnit. Old tests are implemented with JUnit 4 and run using junit-vintage-engine, but
new tests should use JUnit 5 or 6.

LZ4Factory does not always return the implementation you might expect, for security reasons. Make sure you use the 
right LZ4Factory method to construct the implementation you want to test.

## Fuzz testing

Fuzz tests are implemented using the jazzer junit integration. Some tips:

- To get a variable-length array, avoid length-prefix patterns (`consumeBytes(consumeInt(...))`). Instead, either use
`consumeRemainingBytes`, or `consumeBytes` until some pre-defined delimiter. This makes input mutation work better.
- When there are multiple implementations to test, e.g. JNI vs Unsafe vs Safe, or fast decompressor vs safe 
decompressor, or high compression vs fast compression, DO NOT use loops to test them all at once. Instead, create a 
separate fuzz test for each implementation, as fine-grained as possible.
- Make sure to use the right `LZ4Factory` methods as described in the unit testing section.
- Each fuzz test MUST have its own test execution in the pom fuzz profile so that it runs independently.
- When running fuzz tests as part of normal development, limit the jazzer.max_duration to 5s so that you don't spend 
too much time, unless requested to run them for longer.
- When you encounter a fuzzer failure that is *not* a normal recoverable exception (e.g. LZ4Exception, 
ArrayIndexOutOfBoundsException), you MUST treat this as a legitimate failure. In particular, segmentation faults,
UnsafeSanitizer failures, and other sanitizer failures are real. You MUST NOT attempt to alter the fuzz test to make 
them disappear.
