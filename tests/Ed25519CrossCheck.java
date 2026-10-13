// Independent, dependency-free provider cross-check for AURAL's Ed25519 acceptance policy.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

public final class Ed25519CrossCheck {
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(
        new BigInteger("27742317777372353535851937790883648493"));
    private static final Set<BigInteger> SMALL_ORDER_Y = Set.of(
        BigInteger.ZERO,
        BigInteger.ONE,
        P.subtract(BigInteger.ONE),
        new BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
        new BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16)
    );
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private static BigInteger littleEndian(byte[] encoded) {
        byte[] reversed = encoded.clone();
        for (int left = 0, right = reversed.length - 1; left < right; left++, right--) {
            byte temporary = reversed[left];
            reversed[left] = reversed[right];
            reversed[right] = temporary;
        }
        return new BigInteger(1, reversed);
    }

    private static boolean pointProfile(byte[] encoded) {
        if (encoded.length != 32) return false;
        int sign = (encoded[31] & 0xff) >>> 7;
        byte[] yBytes = encoded.clone();
        yBytes[31] &= 0x7f;
        BigInteger y = littleEndian(yBytes);
        if (y.compareTo(P) >= 0 || sign == 1 && (y.equals(BigInteger.ONE)
                || y.equals(P.subtract(BigInteger.ONE)))) return false;
        return !SMALL_ORDER_Y.contains(y);
    }

    private static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (signature.length != 64 || !pointProfile(publicKey)
                || !pointProfile(Arrays.copyOfRange(signature, 0, 32))
                || littleEndian(Arrays.copyOfRange(signature, 32, 64)).compareTo(L) >= 0) return false;
        try {
            byte[] spki = new byte[SPKI_PREFIX.length + publicKey.length];
            System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
            System.arraycopy(publicKey, 0, spki, SPKI_PREFIX.length, publicKey.length);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception error) {
            return false;
        }
    }

    public static void main(String[] arguments) throws Exception {
        Provider provider = Signature.getInstance("Ed25519").getProvider();
        System.out.println("PROVIDER:" + provider.getName() + " " + provider.getVersionStr());
        HexFormat hex = HexFormat.of();
        try (BufferedReader input = new BufferedReader(new InputStreamReader(System.in))) {
            for (String line; (line = input.readLine()) != null;) {
                String[] fields = line.split(" ", -1);
                if (fields.length != 3) throw new IllegalArgumentException("expected key message signature");
                System.out.println(verify(
                    hex.parseHex(fields[0]), hex.parseHex(fields[1]), hex.parseHex(fields[2])) ? "1" : "0");
            }
        }
    }
}
