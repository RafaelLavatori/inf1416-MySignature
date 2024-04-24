/*
Trabalho 3 INF1416 - MySignature

Nome: Rafael Lavatori Caetano de Bastos     Matrícula: 2010818
Nome: João Quintella do Couto               Matrícula: 2010798

*/

import java.security.*;

public class MySignatureTest {

    public static KeyPair generateKeyPair(String key_algorithm) throws Exception {
        // gera um par de chaves
        System.out.println( "\nStart generating key" );
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(key_algorithm);
        keyGen.initialize(2048);
        KeyPair key = keyGen.generateKeyPair();
        System.out.println( "Finish generating key" );

        return key;
    }
    
    public static void main (String[] args) throws Exception {

        //check args
        if (args.length != 2) {
          System.err.println("Usage: MySignatureTest<SP>(signature method)<SP>(string to sign)");
          System.exit(1);
        }
        
        if (!args[0].equals("MD5withRSA") &&
                !args[0].equals("SHA1withRSA") &&
                !args[0].equals("SHA256withRSA") &&
                !args[0].equals("SHA256withECDSA") &&
                !args[0].equals("SHA512withRSA")) {
            System.err.println("Método de assinatura inválido\nMétodos suportados: MD5withRSA, SHA1withRSA, SHA256withRSA, SHA256withECDSA, SHA512withRSA");
            System.exit(2);
        }
        
        String signature_method = args[0];
        byte[] unsigned_data = args[1].getBytes("UTF8");

        // instância Signature
        MySignature signature = MySignature.getInstance(signature_method);
        String key_algorithm = signature.getKeyAlgorithm();

        // gerando chaves
        KeyPair key = generateKeyPair(key_algorithm);

        // inicializando signature
        System.out.println("\nStart encryption");
        signature.update(unsigned_data);
        signature.initSign(key.getPrivate());

        // assinando
        byte[] signed_data = signature.sign();
        System.out.println("Finish encryption (hex output): ");

        // converte o texto cifrado para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < signed_data.length; i++) {
            String hex = Integer.toHexString(0x0100 + (signed_data[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        // imprime o texto cifrado em hexadecimal
        System.out.println(buf.toString());

        // verificando
        signature.update(unsigned_data);
        signature.initVerify(key.getPublic());
        boolean isSignatureLegit = signature.verify(signed_data);

        if (isSignatureLegit) System.out.println("Signature is legitimate");
        else System.out.println("Signature is not legitimate");

    }
}
