import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

public class BlockData {
    private String universityName;
    private HashMap<Integer, PublicKey> diplomaPublicKeyMap;
    private KeyPair universityKeys;

    public static final int KEYSIZE = 571;

    // Algorithm Name 	Description
    //---------------------------------------------------------
    // DiffieHellman 	Generates keypairs for the Diffie-Hellman KeyAgreement algorithm.
    //                  Note: key.getAlgorithm() will return "DH" instead of "DiffieHellman".
    // DSA 	Generates keypairs for the Digital Signature Algorithm.
    // RSA 	Generates keypairs for the RSA algorithm (Signature/Cipher).
    // EC 	Generates keypairs for the Elliptic Curve algorithm.
    //----------------------------------------------------------
    private String keyGenAlgorithmString = "EC";

    public BlockData(String universityName) throws Exception {
        this.universityName = universityName;
        this.diplomaPublicKeyMap = new HashMap<>();
        initKeys();
    }

    public String getUniversityName() {
        return universityName;
    }

    public HashMap<Integer, PublicKey> getDiplomaPublicKeyMap() {
        return diplomaPublicKeyMap;
    }

    public PublicKey getUniversityPublicKey() {
        return this.universityKeys.getPublic();
    }

    public String getDecryptedDiploma(String encryptedDiplomaStr, PublicKey diplomaPublicKey) throws Exception {
        return decryptDiploma(this.universityKeys, diplomaPublicKey, encryptedDiplomaStr);
    }

    private void initKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyGenAlgorithmString);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(KEYSIZE, random);

        this.universityKeys = keyGen.generateKeyPair();
    }

    /*
     *
     */
    private String decryptDiploma(KeyPair keyPair, PublicKey publicKey, String message) throws Exception {
        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory kf = KeyFactory.getInstance(keyGenAlgorithmString);
        ECPublicKey ephemeralPublicKey = (ECPublicKey)kf.generatePublic(ks);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH");
        aKeyAgree.init(keyPair.getPrivate());
        aKeyAgree.doPhase(ephemeralPublicKey, true);

        byte[] sharedSecret = aKeyAgree.generateSecret();
        // System.out.println("decrypt sharedSecret:"+new String(Base64.encode(sharedSecret)));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyMaterial = digest.digest(sharedSecret);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyMaterial, "AES")/*,
        new IvParameterSpec(iv)*/
        );
        return new String(cipher.doFinal(Base64.getDecoder().decode(message)));
    }

}
