package net.jpountz.lz4;

/*
 * Copyright 2025 Jonas Konrad and the lz4-java contributors.
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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;

public class OutOfBoundsTest {
  public static Collection<Object[]> parameters() {
    return Arrays.asList(
      new Object[]{LZ4Factory.fastestInstance().fastDecompressor()},
      new Object[]{LZ4Factory.fastestJavaInstance().fastDecompressor()},
      new Object[]{LZ4Factory.nativeInstance().fastDecompressor()},
      new Object[]{LZ4Factory.safeInstance().fastDecompressor()},
      new Object[]{LZ4Factory.unsafeInstance().fastDecompressor()}
    );
  }

  @ParameterizedTest
  @MethodSource("parameters")
  public void test(LZ4FastDecompressor fastDecompressor) {
    byte[] output = new byte[2055];
    for (int i = 0; i < 1000000; i++) {
      try {
        fastDecompressor.decompress(new byte[]{
          (byte) 0xf0,
          -1, -1, -1, -1, -1, -1, -1, -1, 0
        }, output);
      } catch (LZ4Exception ignored) {
      }
    }
  }
}
