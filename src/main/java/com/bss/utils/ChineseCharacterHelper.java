/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.io.UnsupportedEncodingException;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class ChineseCharacterHelper
/*    */ {
/*    */   static final int GB_SP_DIFF = 160;
/* 11 */   static final int[] secPosValueList = new int[] { 1601, 1637, 1833, 2078, 2274, 2302, 2433, 2594, 2787, 3106, 3212, 3472, 3635, 3722, 3730, 3858, 4027, 4086, 4390, 4558, 4684, 4925, 5249, 5600 };
/*    */ 
/*    */   
/* 14 */   static final char[] firstLetter = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'W', 'X', 'Y', 'Z' };
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String getSpells(String characters) {
/* 23 */     StringBuffer buffer = new StringBuffer();
/* 24 */     for (int i = 0; i < characters.length(); i++) {
/*    */       
/* 26 */       char ch = characters.charAt(i);
/* 27 */       if (ch >> 7 == 0) {
/*    */         
/* 29 */         buffer.append(ch);
/*    */       } else {
/* 31 */         char spell = getFirstLetter(ch).charValue();
/* 32 */         buffer.append(String.valueOf(spell));
/*    */       } 
/*    */     } 
/* 35 */     return buffer.toString();
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static Character getFirstLetter(char ch) {
/* 45 */     byte[] uniCode = null;
/*    */     try {
/* 47 */       uniCode = String.valueOf(ch).getBytes("GBK");
/* 48 */     } catch (UnsupportedEncodingException e) {
/* 49 */       e.printStackTrace();
/* 50 */       return null;
/*    */     } 
/* 52 */     if (uniCode[0] < 128 && uniCode[0] > 0) {
/* 53 */       return null;
/*    */     }
/* 55 */     return Character.valueOf(convert(uniCode));
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   private static char convert(byte[] bytes) {
/* 65 */     char result = '#';
/* 66 */     int secPosValue = 0;
/*    */     int i;
/* 68 */     for (i = 0; i < bytes.length; i++) {
/* 69 */       bytes[i] = (byte)(bytes[i] - 160);
/*    */     }
/* 71 */     secPosValue = bytes[0] * 100 + bytes[1];
/* 72 */     for (i = 0; i < 23; i++) {
/* 73 */       if (secPosValue >= secPosValueList[i] && secPosValue < secPosValueList[i + 1]) {
/* 74 */         result = firstLetter[i];
/*    */         break;
/*    */       } 
/*    */     } 
/* 78 */     return result;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\ChineseCharacterHelper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */