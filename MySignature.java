/*
Trabalho 3 INF1416 - MySignature

Nome: Rafael Lavatori Caetano de Bastos     Matrícula: 2010818
Nome: João Quintella do Couto               Matrícula: 2010798

*/

import java.security.*;
import javax.crypto.*;
import java.util.*;

public class MySignature{
    
    private PrivateKey privatekey;
    private PublicKey publickey;
    private MessageDigest messagedigest;
    private Cipher cipher;
    private byte[] data; 
    
    public static MySignature getInstance(String args) throws Exception {
        
        String[] signature_pattern = args.split("with");
        if (signature_pattern.length != 2) {
            throw new Exception("Invalid Signature Pattern");
        }
        
        String digest_alg = signature_pattern[0];
        String key_alg = signature_pattern[1];
        
        if (
            (!digest_alg.equals("MD5") &&
                !digest_alg.equals("SHA1") &&
                !digest_alg.equals("SHA256") &&
                !digest_alg.equals("SHA512") &&
                !key_alg.equals("RSA")
            ) &&
            (!digest_alg.equals("SHA256") &&
                !key_alg.equals("ECDSA"))
        ) {
            throw new Exception("Invalid Signature Pattern");
        }
        
        MySignature instance = new MySignature();
        instance.messagedigest = MessageDigest.getInstance(digest_alg);
        instance.cipher = Cipher.getInstance(key_alg + "ECB/PKCS1Padding");
        
        return instance; 
    }
    
    public void initSign(PrivateKey private_key){
        this.privatekey = private_key;
    }
    
    public void update(byte[] input_data){
        this.data = input_data;
    }
    
    public byte[] sign() throws Exception{
        
        byte[] digest = this.messagedigest.digest(this.data);
        
        this.cipher.init(Cipher.ENCRYPT_MODE, this.privatekey);
        byte[] encrypted_data = this.cipher.doFinal(digest);
        
        this.data = null; 
        
        return encrypted_data; 
    }
    
    public void initVerify(PublicKey public_key){
        this.publickey = public_key;
    }
    
    public boolean verify(byte[] signature) throws Exception{
        
        byte[] digest = this.messagedigest.digest(this.data);

        this.cipher.init(Cipher.DECRYPT_MODE, this.publickey);
        byte[] decrypted_data = this.cipher.doFinal(signature);
        
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

