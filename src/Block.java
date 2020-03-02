import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class Block {

    private String hash;
    private String previousHash;
    private BlockData blockData;

    private String encryptedData;
    public long timeStamp; //as number of milliseconds since 1/1/1970.
    private int nonce;
    KeyPair wtTestKeys;
    KeyPair deviceKeys;

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

    //Block Constructor.
    public Block(BlockData data, String previousHash ) throws Exception {
        initKeys();
        this.blockData = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();

        this.hash = calculateHash(); //Making sure we do this after we set the other values.
    }

    //Calculate new hash based on blocks contents
    public String calculateHash() {
        System.out.println("calculateHash time!!! : " + timeStamp);
        String calculatedhash = StringUtil.applySha256(
                previousHash +
                        Long.toString(timeStamp) +
                        Integer.toString(nonce) +
                        encryptedData
        );
        return calculatedhash;
    }

    //Increases nonce value until hash target is reached.
    public void mineBlock(int difficulty) {
        String target = StringUtil.getDificultyString(difficulty); //Create a string with difficulty * "0"
        while(!hash.substring( 0, difficulty).equals(target)) {
            nonce ++;
            hash = calculateHash();
        }
        System.out.println("Block Mined!!! : " + hash);
    }

    public String getDataBack() throws Exception{
        return  decryptMessage(wtTestKeys, deviceKeys.getPublic(), encryptedData);
    }

    private void initKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyGenAlgorithmString);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(KEYSIZE, random);

        this.wtTestKeys = keyGen.generateKeyPair();
        this.deviceKeys = keyGen.generateKeyPair();
    }

    /*
     *
     */
    private String decryptMessage(KeyPair keyPair, PublicKey publicKey, String message) throws Exception {
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

    /*
     *
     */

    private String encryptMessage(KeyPair keyPair, PublicKey publicKey, Diploma diploma) throws Exception{
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

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public BlockData getBlockData() {
        return blockData;
    }

    public void setBlockData(BlockData blockData) {
        this.blockData = blockData;
    }
}
