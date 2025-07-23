/*    */ package com.bss.sdk.utils;
/*    */ 
/*    */ import java.security.SecureRandom;
/*    */ import java.util.Random;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class StringUtils
/*    */ {
/*    */   private static final String ALPHAMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/*    */   
/*    */   public static boolean isNotBlank(CharSequence cs) {
/* 15 */     return !isBlank(cs);
/*    */   }
/*    */   
/*    */   public static boolean isEmpty(CharSequence cs) {
/* 19 */     return isBlank(cs);
/*    */   }
/*    */   
/*    */   public static boolean isBlank(CharSequence cs) {
/*    */     int strLen;
/* 24 */     if (cs != null && (strLen = cs.length()) != 0) {
/* 25 */       for (int i = 0; i < strLen; i++) {
/* 26 */         if (!Character.isWhitespace(cs.charAt(i))) {
/* 27 */           return false;
/*    */         }
/*    */       } 
/*    */       
/* 31 */       return true;
/*    */     } 
/* 33 */     return true;
/*    */   }
/*    */ 
/*    */   
/*    */   public static String genRandomString(int length) {
/* 38 */     Random random = new SecureRandom();
/* 39 */     StringBuilder sb = new StringBuilder();
/*    */     
/* 41 */     for (int i = 0; i < length; i++) {
/* 42 */       int number = random.nextInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length());
/* 43 */       sb.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(number));
/*    */     } 
/*    */     
/* 46 */     return sb.toString();
/*    */   }
/*    */   
/*    */   public static String genRandomNumber(int length) {
/* 50 */     String numberStr = "0123456789";
/* 51 */     Random random = new SecureRandom();
/* 52 */     StringBuilder sb = new StringBuilder();
/*    */     
/* 54 */     for (int i = 0; i < length; i++) {
/* 55 */       int number = random.nextInt(numberStr.length());
/* 56 */       sb.append(numberStr.charAt(number));
/*    */     } 
/*    */     
/* 59 */     return sb.toString();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\StringUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */