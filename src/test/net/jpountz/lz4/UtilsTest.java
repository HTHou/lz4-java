package net.jpountz.lz4;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UtilsTest {
  @Test
  public void matchRunLength() {
    byte[] arr = new byte[1024 * 1024];
    for (int toEncode = 0; toEncode < 1000000; toEncode++) {
      int expected = LZ4Utils.lengthOfEncodedInteger(toEncode);
      int n = toEncode >= 15 ? LZ4SafeUtils.writeLen(toEncode - 15, arr, 0) : 0;
      int finalToEncode = toEncode;
      assertEquals(expected, n, () -> String.valueOf(finalToEncode));
    }
  }

  @Test
  public void testEncodeSequence() {
    int runLength = 16;
    byte[] dest = new byte[1 + LZ4Utils.lengthOfEncodedInteger(runLength) + runLength + 2 + (1 + LZ4Constants.LAST_LITERALS)];
    LZ4UnsafeUtils.encodeSequence(
      new byte[runLength],
      0,
      runLength,
      0,
      0,
      dest,
      0,
      dest.length
    );
  }
}
