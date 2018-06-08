package au.com.acegi.hashbench.hashers;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;

public class GHASHHasher implements Hasher {
  public static final String GHASH_NAME = "ghash";

  public static final void register(final Map<String, Hasher> hashers) {
    try {
        hashers.put(GHASHHasher.GHASH_NAME, new GHASHHasher());
    } catch (Exception e) {
        System.err.println("trying register GHASHHasher: " + e);
          e.printStackTrace();
          System.exit(1);
    }
  }

  private final Constructor<?> GHASH;
  private final Object ghash;
  private final Method UPDATE;
  private final Method DIGEST;
  private final Method RESET;
  
  void update(byte[] b, int off, int len) {
      try {
        UPDATE.invoke(ghash, b, off, len);
      } catch (Exception e) {
          System.err.println("GHASH update: " + e);
          e.printStackTrace();
          System.exit(1);
      }
  }

  long digest() {
      try {
        byte [] d = (byte[]) DIGEST.invoke(ghash);
        long res = 0;
        for (byte x : d) {
            res >>>= 8;
            res ^= x;
        }
        return res;
      } catch (Exception e) {
          System.err.println("GHASH digest: " + e);
          e.printStackTrace();
          System.exit(1);
      }
      return 0;
  }
  
  void update(byte[] b) {
      update(b, 0, b.length);
  }

  void reset() {
      try {
        RESET.invoke(ghash);
      } catch (Exception e) {
          System.err.println("GHASH reset: " + e);
          e.printStackTrace();
          System.exit(1);
      }
  }

  private GHASHHasher() throws Exception {
    String test_class = "com.sun.crypto.provider.GHASH";
    Class<?> cls = Class.forName(test_class);
    GHASH = cls.getDeclaredConstructor(byte[].class);
    GHASH.setAccessible(true);
    UPDATE = cls.getDeclaredMethod("update", byte[].class, int.class, int.class);
    UPDATE.setAccessible(true);
    DIGEST = cls.getDeclaredMethod("digest");
    DIGEST.setAccessible(true);
    RESET = cls.getDeclaredMethod("reset");
    RESET.setAccessible(true);
    byte subkeyH[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
//    System.out.println("GHASH constructor: " + GHASH.toString() );
    ghash = GHASH.newInstance(subkeyH);
  }

  @Override
  public long hash(final byte[] in, final int off, final int len) {
//    System.out.println("hash: len = " + len + " , off = " + off);
    this.reset();
    this.update(in, off, len);
    return this.digest();
  }

  @Override
  public long hash(final ByteBuffer bb, final int off, final int len) {
//    System.out.println("hash(bb): len = " + len + " , off = " + off + ", bb.remaining = " + bb.remaining());
    this.reset();

    if (bb.hasArray()) {
      this.update(bb.array(), off, len);
      return this.digest();
    }

    final ByteBuffer view = bb.duplicate();
    view.position(off);
    view.limit(off + len);


    byte[] v = new byte[len];
    view.get(v);
    
//    System.out.println("view.limit = " + view.limit() + ", view.remaining = " + view.remaining());
    
    this.update(v);
    return this.digest();
  }
}
