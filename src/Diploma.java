import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

enum DEGREE_TYPE {BACHELOR, MASTER, PHD}

public class Diploma {
    private String name;
    private int studentId;
    private Date graduateDate;
    private DEGREE_TYPE degreeType;
    private String universityName;
    private PublicKey universityPublicKey;
    private String encryptedDiploma;
    private String previousHash;
    KeyPair diplomaKeys;
    //KeyPair deviceKeys;

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

    public Diploma(String name, int studentId, Date graduateDate, DEGREE_TYPE degreeType,
                   String universityName, PublicKey universityPublicKey, String previousHash) throws Exception {
        this.name = name;
        this.studentId = studentId;
        this.graduateDate = graduateDate;
        this.degreeType = degreeType;
        this.universityName = universityName;
        this.universityPublicKey = universityPublicKey;
        this.previousHash = previousHash;
        initKeys();
        this.encryptedDiploma = encryptDiploma(this.diplomaKeys, this.universityPublicKey, this);
    }

    @Override
    public String toString() {
        return "Diploma{" +
                "name='" + name + '\'' +
                ", studentId='" + studentId + '\'' +
                ", graduateDate=" + graduateDate +
                ", degreeType=" + degreeType +
                ", universityName='" + universityName + '\'' +
                '}';
    }

    public String getUniversityName() {
        return universityName;
    }

    public PublicKey getPublicKey() {
        return this.diplomaKeys.getPublic();
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public int getMapKey(){
        return this.studentId;
    }

    public String getEncryptedDiploma() throws Exception {
       return this.encryptedDiploma;
    }

    private void initKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyGenAlgorithmString);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(KEYSIZE, random);

        this.diplomaKeys = keyGen.generateKeyPair();
        //this.deviceKeys = keyGen.generateKeyPair();
    }

    /*
     *
     */
    private String encryptDiploma(KeyPair keyPair, PublicKey publicKey, Diploma diploma) throws Exception{
        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory kf = KeyFactory.getInstance(keyGenAlgorithmString);
        ECPublicKey ephemeralPublicKey = (ECPublicKey)kf.generatePublic(ks);
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH");
        aKeyAgree.init(keyPair.getPrivate());
        aKeyAgree.doPhase(ephemeralPublicKey, true);
        byte[] sharedSecret = aKeyAgree.generateSecret();

        System.out.println("encrypt sharedSecret:\n"+new String(Base64.getEncoder().encode(sharedSecret)));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyMaterial = digest.digest(sharedSecret);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyMaterial, "AES")/*,
        new IvParameterSpec(iv)*/
        );
        return new String(Base64.getEncoder().encode(cipher.doFinal(diploma.toString().getBytes())));
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
