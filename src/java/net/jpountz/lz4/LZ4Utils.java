package net.jpountz.lz4;

/*
 * Copyright 2020 Adrien Grand and the lz4-java contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import static net.jpountz.lz4.LZ4Constants.HASH_LOG;
import static net.jpountz.lz4.LZ4Constants.HASH_LOG_64K;
import static net.jpountz.lz4.LZ4Constants.HASH_LOG_HC;
import static net.jpountz.lz4.LZ4Constants.MIN_MATCH;

enum LZ4Utils {
  ;

  private static final int MAX_INPUT_SIZE = 0x7E000000;

  static int maxCompressedLength(int length) {
    if (length < 0) {
      throw new IllegalArgumentException("length must be >= 0, got " + length);
    } else if (length >= MAX_INPUT_SIZE) {
        throw new IllegalArgumentException("length must be < " + MAX_INPUT_SIZE);
    }
    return length + length / 255 + 16;
  }

  /**
   * The LZ4 format uses two integers per sequence, encoded in a special format: 4 bits in a shared "token" byte, and
   * then possibly multiple additional bytes. This method returns the number of bytes used to encode a particular
   * value, excluding the 4 shared bits. This is the exact length of the encoding {@link LZ4SafeUtils#writeLen} and
   * equivalent methods implement.
   */
  static int lengthOfEncodedInteger(int value) {
    if (value >= 15) {
      return (value - 15) / 0xff + 1;
    } else {
      return 0;
    }
  }

  /**
   * Get the length of an encoded LZ4 sequence. An LZ4 sequence consists of a <i>run</i>, containing bytes that are
   * copied from the compressed input as-is, and a <i>match</i> which is a reference to previously decompressed bytes.
   * <p>
   * Encoding:
   *
   * <ul>
   *   <li>1 byte: Token containing 4 bits of the run length and match length each</li>
   *   <li>Possibly more bytes to encode the run length</li>
   *   <li>The run bytes</li>
   *   <li>2 bytes: Match offset</li>
   *   <li>Possibly more bytes to encode the match length</li>
   * </ul>
   */
  static int sequenceLength(int runLen, int matchLen) {
    return 1 + lengthOfEncodedInteger(runLen) + runLen + 2 + lengthOfEncodedInteger(matchLen);
  }

  static int hash(int i) {
    return (i * -1640531535) >>> ((MIN_MATCH * 8) - HASH_LOG);
  }

  static int hash64k(int i) {
    return (i * -1640531535) >>> ((MIN_MATCH * 8) - HASH_LOG_64K);
  }

  static int hashHC(int i) {
    return (i * -1640531535) >>> ((MIN_MATCH * 8) - HASH_LOG_HC);
  }

  static class Match {
    int start, ref, len;

    void fix(int correction) {
      start += correction;
      ref += correction;
      len -= correction;
    }

    int end() {
      return start + len;
    }
  }

  static void copyTo(Match m1, Match m2) {
    m2.len = m1.len;
    m2.start = m1.start;
    m2.ref = m1.ref;
  }

}
