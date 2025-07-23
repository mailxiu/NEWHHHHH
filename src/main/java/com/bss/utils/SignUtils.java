/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.security.MessageDigest;
/*    */ import java.util.ArrayList;
/*    */ import java.util.Collections;
/*    */ import java.util.List;
/*    */ import java.util.Map;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class SignUtils
/*    */ {
/*    */   public static String signature(Map<String, Object> params, String key) {
/* 19 */     String signatures = "";
/*    */     try {
/* 21 */       List<String> paramsStr = new ArrayList<>();
/* 22 */       for (String key1 : params.keySet()) {
/* 23 */         if (null != key1 && !"".equals(key1) && !"sign".equals(key1)) {
/* 24 */           paramsStr.add(key1);
/*    */         }
/*    */       } 
/* 27 */       Collections.sort(paramsStr);
/* 28 */       StringBuilder sbff = new StringBuilder();
/* 29 */       for (String kk : paramsStr) {
/* 30 */         if (params.get(kk) == null) {
/*    */           continue;
/*    */         }
/* 33 */         String value = params.get(kk).toString();
/* 34 */         if ("".equals(sbff.toString())) {
/* 35 */           sbff.append(kk + "=" + value); continue;
/*    */         } 
/* 37 */         sbff.append("&" + kk + "=" + value);
/*    */       } 
/*    */ 
/*    */       
/* 41 */       StringBuilder append = sbff.append("&key=" + key);
/*    */       
/* 43 */       signatures = getMD5(sbff.toString()).toUpperCase();
/* 44 */     } catch (Exception e) {
/* 45 */       e.printStackTrace();
/*    */     } 
/* 47 */     return signatures;
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String getMD5(String message) {
/* 58 */     String md5 = "";
/*    */     try {
/* 60 */       MessageDigest md = MessageDigest.getInstance("MD5");
/* 61 */       byte[] messageByte = message.getBytes("UTF-8");
/* 62 */       byte[] md5Byte = md.digest(messageByte);
/* 63 */       md5 = bytesToHex(md5Byte);
/* 64 */     } catch (Exception e) {
/* 65 */       e.printStackTrace();
/*    */     } 
/* 67 */     return md5;
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String bytesToHex(byte[] bytes) {
/* 78 */     StringBuffer hexStr = new StringBuffer();
/*    */     
/* 80 */     for (int i = 0; i < bytes.length; i++) {
/* 81 */       int num = bytes[i];
/* 82 */       if (num < 0) {
/* 83 */         num += 256;
/*    */       }
/* 85 */       if (num < 16) {
/* 86 */         hexStr.append("0");
/*    */       }
/* 88 */       hexStr.append(Integer.toHexString(num));
/*    */     } 
/* 90 */     return hexStr.toString().toUpperCase();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\SignUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */