/*     */ package com.bss.sdk.utils;
/*     */ 
/*     */ import com.bss.sdk.exception.SandPayException;
/*     */
/*     */
/*     */ import java.io.ByteArrayInputStream;
/*     */ import java.io.ByteArrayOutputStream;
/*     */ import java.io.InputStream;
/*     */ import java.nio.charset.StandardCharsets;
/*     */ import java.security.KeyStore;
/*     */ import java.security.PrivateKey;
/*     */ import java.security.PublicKey;
/*     */ import java.security.Signature;
/*     */ import java.security.cert.CertificateFactory;
/*     */ import java.security.cert.X509Certificate;
/*     */ import java.util.Enumeration;
/*     */ import java.util.Objects;
/*     */ import javax.crypto.Cipher;
/*     */ import org.apache.tomcat.util.codec.binary.Base64;
/*     */ 
/*     */ 
/*     */ 
/*     */ public class RSAUtils
/*     */ {
/*     */   private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
/*     */   private static final int KEY_LENGTH = 2048;
/*     */   private static final int RESERVE_SIZE = 11;
/*     */   
/*     */   public static String encryptToBase64Text(String plainTextBytes, PublicKey publicKey) throws Exception {
/*  30 */     byte[] aesKeyBytes = plainTextBytes.getBytes();
/*  31 */     byte[] encryptKeyBytes = encrypt(aesKeyBytes, publicKey);
/*  32 */     return Base64.encodeBase64String(encryptKeyBytes);
/*     */   }
/*     */   
/*     */   public static String decryptBase64ToText(String encText, PrivateKey privateKey) throws Exception {
/*  36 */     byte[] encTextBytes = Base64.decodeBase64(encText);
/*  37 */     byte[] contentBytes = decrypt(encTextBytes, privateKey);
/*  38 */     String decryptText = new String(contentBytes, StandardCharsets.UTF_8);
/*  39 */     return decryptText;
/*     */   }
/*     */   
/*     */   public static byte[] encrypt(byte[] plainTextBytes, PublicKey publicKey) throws Exception {
/*  43 */     boolean keyByteSize = true;
/*  44 */     boolean encryptBlockSize = true;
/*  45 */     int nBlock = plainTextBytes.length / 245;
/*  46 */     if (plainTextBytes.length % 245 != 0) {
/*  47 */       nBlock++;
/*     */     }
/*     */     
/*  50 */     Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
/*  51 */     cipher.init(1, publicKey);
/*  52 */     ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(nBlock * 256);
/*     */     
/*  54 */     for (int offset = 0; offset < plainTextBytes.length; offset += 245) {
/*  55 */       int inputLen = plainTextBytes.length - offset;
/*  56 */       if (inputLen > 245) {
/*  57 */         inputLen = 245;
/*     */       }
/*     */       
/*  60 */       byte[] decryptedBlock = cipher.doFinal(plainTextBytes, offset, inputLen);
/*  61 */       byteArrayOutputStream.write(decryptedBlock);
/*     */     } 
/*     */     
/*  64 */     byteArrayOutputStream.flush();
/*  65 */     byteArrayOutputStream.close();
/*  66 */     return byteArrayOutputStream.toByteArray();
/*     */   }
/*     */   
/*     */   public static byte[] decrypt(byte[] cipherTextBytes, PrivateKey privateKey) throws Exception {
/*  70 */     boolean keyByteSize = true;
/*  71 */     boolean decryptBlockSize = true;
/*  72 */     int nBlock = cipherTextBytes.length / 256;
/*  73 */     Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
/*  74 */     cipher.init(2, privateKey);
/*  75 */     ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(nBlock * 245);
/*     */     
/*  77 */     for (int offset = 0; offset < cipherTextBytes.length; offset += 256) {
/*  78 */       int inputLen = cipherTextBytes.length - offset;
/*  79 */       if (inputLen > 256) {
/*  80 */         inputLen = 256;
/*     */       }
/*     */       
/*  83 */       byte[] decryptedBlock = cipher.doFinal(cipherTextBytes, offset, inputLen);
/*  84 */       byteArrayOutputStream.write(decryptedBlock);
/*     */     } 
/*     */     
/*  87 */     byteArrayOutputStream.flush();
/*  88 */     byteArrayOutputStream.close();
/*  89 */     return byteArrayOutputStream.toByteArray();
/*     */   }
/*     */   
/*     */   public static String generateSign(String content, PrivateKey privateKey, String signType, String charset) throws Exception {
/*  93 */     Signature signature = null;
/*  94 */     if (!"RSA".equals(signType) && !"SHA256WithRSA".equals(signType)) {
/*  95 */       throw new SandPayException("不是支持的签名类型 : signType=" + signType);
/*     */     }
/*  97 */     signature = Signature.getInstance("SHA256WithRSA");
/*  98 */     signature.initSign(privateKey);
/*  99 */     if (StringUtils.isBlank(charset)) {
/* 100 */       signature.update(content.getBytes());
/*     */     } else {
/* 102 */       signature.update(content.getBytes(charset));
/*     */     } 
/*     */     
/* 105 */     byte[] signed = signature.sign();
/* 106 */     return Base64.encodeBase64String(signed);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public static boolean verifySign(String content, String sign, String signType, PublicKey publicKey, String charset) throws Exception {
/* 119 */     Signature signature = Signature.getInstance(signType);
/* 120 */     signature.initVerify(publicKey);
/* 121 */     if (StringUtils.isBlank(charset)) {
/* 122 */       signature.update(content.getBytes());
/*     */     } else {
/* 124 */       signature.update(content.getBytes(charset));
/*     */     } 
/* 126 */     return signature.verify(Base64.decodeBase64(sign.getBytes()));
/*     */   }
/*     */   
/*     */   public static PublicKey getPublicKeyByStr(String publicKeyStr) throws Exception {
/* 130 */     return loadPublicKey(new ByteArrayInputStream(publicKeyStr.getBytes()));
/*     */   }
/*     */   
/*     */   public static PrivateKey getPrivateKeyByStr(String priKeyStr) throws Exception {
/* 134 */     return loadPrivateKey(new ByteArrayInputStream(priKeyStr.getBytes()), (String)null);
/*     */   }
/*     */   public static PrivateKey loadPrivateKey(InputStream ins, String password) throws Exception {
/*     */     char[] nPassword;
/* 138 */     KeyStore ks = KeyStore.getInstance("PKCS12");
/*     */     
/* 140 */     if (password != null && !password.trim().equals("")) {
/* 141 */       nPassword = password.toCharArray();
/*     */     } else {
/* 143 */       nPassword = null;
/*     */     } 
/*     */     
/* 146 */     ks.load(ins, nPassword);
/* 147 */     Enumeration<String> enumas = ks.aliases();
/* 148 */     String keyAlias = null;
/* 149 */     if (enumas.hasMoreElements()) {
/* 150 */       keyAlias = enumas.nextElement();
/*     */     }
/*     */     
/* 153 */     return (PrivateKey)ks.getKey(keyAlias, nPassword);
/*     */   }
/*     */ 
/*     */   
/*     */   public static PublicKey getSandPublicKey(String sandPublicKeyPath) throws Exception {
/* 158 */     InputStream publicIns = FileUtils.loadFile(sandPublicKeyPath);
/* 159 */     if (Objects.isNull(publicIns)) {
/* 160 */       throw new SandPayException("获取公钥失败");
/*     */     }
/* 162 */     return loadPublicKey(publicIns);
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   public static PublicKey loadPublicKey(InputStream ins) throws Exception {
/* 168 */     CertificateFactory cf = CertificateFactory.getInstance("X.509");
/* 169 */     X509Certificate oCert = (X509Certificate)cf.generateCertificate(ins);
/* 170 */     PublicKey publicKey = oCert.getPublicKey();
/* 171 */     return publicKey;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\RSAUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */