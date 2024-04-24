/*
Trabalho 3 INF1416 - MySignature

Nome: Rafael Lavatori Caetano de Bastos     Matrícula: 2010818
Nome: João Quintella do Couto               Matrícula: 2010798

*/

import java.security.*;
import javax.crypto.*;

public class MySignature{
    
    private PrivateKey privatekey;
    private PublicKey publickey;
    private MessageDigest messagedigest;
    private Cipher cipher;
    private byte[] data;
    
    private String digestAlgorithm;
    private String keyAlgorithm;
    
    public static MySignature getInstance(String args) throws Exception {
        
        if (!args.equals("MD5withRSA") &&
                !args.equals("SHA1withRSA") &&
                !args.equals("SHA256withRSA") &&
                !args.equals("SHA256withECDSA") &&
                !args.equals("SHA512withRSA")) {
            System.err.println("Método de assinatura inválido\nMétodos suportados: MD5withRSA, SHA1withRSA, SHA256withRSA, SHA256withECDSA, SHA512withRSA");
            System.exit(3);
        }
        
        String[] signature_pattern = args.split("with");
        if (signature_pattern.length != 2) {
            throw new Exception("Invalid Signature Pattern");
        }
        
        String digest_alg = signature_pattern[0];
        String key_alg = signature_pattern[1];
        
        MySignature instance = new MySignature();
        instance.messagedigest = MessageDigest.getInstance(digest_alg);
        instance.cipher = Cipher.getInstance(key_alg + "/ECB/PKCS1Padding");

        instance.digestAlgorithm = digest_alg;
        instance.keyAlgorithm = key_alg;
        
        return instance; 
    }

    public String getDigestAlgorithm() { return this.digestAlgorithm; }
    public String getKeyAlgorithm() { return this.keyAlgorithm; }
    
    public void initSign(PrivateKey private_key){
        this.privatekey = private_key;
    }
    
    public void update(byte[] input_data){
        this.data = input_data;
    }
    
    public byte[] sign() throws Exception{
        System.out.println("Start generating message digest");
        byte[] digest = this.messagedigest.digest(this.data);

        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < digest.length; i++) {
            String hex = Integer.toHexString(0x0100 + (digest[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }
        System.out.println("Finish generating message digest:");
        System.out.println(buf.toString());
        
        this.cipher.init(Cipher.ENCRYPT_MODE, this.privatekey);
        byte[] encrypted_data = this.cipher.doFinal(digest);
        
        this.data = null; 
        
        return encrypted_data; 
    }
    
    public void initVerify(PublicKey public_key){
        this.publickey = public_key;
    }
    
    public boolean verify(byte[] signature) throws Exception{
        

        System.out.println("\nStart decryption");
        this.cipher.init(Cipher.DECRYPT_MODE, this.publickey);
        byte[] decrypted_data = this.cipher.doFinal(signature);

        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < decrypted_data.length; i++) {
            String hex = Integer.toHexString(0x0100 + (decrypted_data[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }
        System.out.println("Finish decryption:");
        System.out.println(buf.toString());
        
        System.out.println("\nVerifying digest");
        byte[] digest = this.messagedigest.digest(this.data);
        if(digest.length == decrypted_data.length){
            for(int i=0; i<digest.length; i++){
              if(digest[i] != decrypted_data[i]){
                return false;  
              }  
            }
            return true;
        }
        else{
            return false;
        }
    }
}

