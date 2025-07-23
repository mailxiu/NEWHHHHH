/*    */ package com.bss.sdk.utils;
/*    */ 
/*    */

/*    */ import javax.crypto.Cipher;
/*    */ import javax.crypto.SecretKey;
/*    */ import javax.crypto.spec.IvParameterSpec;
/*    */ import javax.crypto.spec.SecretKeySpec;
/*    */ 
/*    */ 
/*    */ 
/*    */ public class AESUtils
/*    */ {
/*    */   private static final String KEY_ALGORITHM = "AES";
/*    */   private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
/*    */   
/*    */   public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, String IV) throws Exception {
/* 17 */     Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
/* 18 */     SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
/* 19 */     if (StringUtils.isNotBlank(IV)) {
/* 20 */       IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
/* 21 */       cipher.init(1, secretKey, ips);
/*    */     } else {
/* 23 */       cipher.init(1, secretKey);
/*    */     } 
/*    */     
/* 26 */     return cipher.doFinal(plainBytes);
/*    */   }
/*    */   
/*    */   public static byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes, String IV) throws Exception {
/* 30 */     Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
/* 31 */     SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
/* 32 */     if (StringUtils.isNotBlank(IV)) {
/* 33 */       IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
/* 34 */       cipher.init(2, secretKey, ips);
/*    */     } else {
/* 36 */       cipher.init(2, secretKey);
/*    */     } 
/*    */     
/* 39 */     return cipher.doFinal(encryptedBytes);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\AESUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */