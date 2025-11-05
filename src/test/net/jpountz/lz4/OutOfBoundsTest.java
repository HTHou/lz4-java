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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OutOfBoundsTest {
  public static Collection<Object[]> fastDecompressor() {
    return Arrays.asList(
      new Object[]{LZ4Factory.fastestInstance().fastDecompressor()},
      new Object[]{LZ4Factory.fastestJavaInstance().fastDecompressor()},
      //new Object[]{LZ4Factory.nativeInsecureInstance().fastDecompressor()},
      new Object[]{LZ4Factory.nativeInstance().fastDecompressor()},
      new Object[]{LZ4Factory.safeInstance().fastDecompressor()},
      new Object[]{LZ4Factory.unsafeInsecureInstance().fastDecompressor()}
    );
  }

  @ParameterizedTest
  @MethodSource("fastDecompressor")
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

  @ParameterizedTest
  @MethodSource("fastDecompressor")
  public void beyondBufferCapacity(LZ4FastDecompressor fastDecompressor) {
    byte[] compressed = new byte[]{
      // one frame with 4x literal 0x77 and a copy of the same
      (byte) 0x40,
      0x77, 0x77, 0x77, 0x77,
      0x04,
      0x00,
      // one frame with 8x literal 0x66
      (byte) 0x80,
      0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x00,
      0x00
    };
    byte[] output = new byte[16];

    // normal decompression. so far so good.
    fastDecompressor.decompress(ByteBuffer.wrap(compressed), ByteBuffer.wrap(output));
    assertEquals(0x77, output[0]);
    assertEquals(0x66, output[8]);

    // but if we only pass half the input size, we should get an error
    assertThrows(LZ4Exception.class, () -> fastDecompressor.decompress(ByteBuffer.wrap(compressed, 0, 7).slice(), 0, ByteBuffer.wrap(output), 0, 16));
  }
}
