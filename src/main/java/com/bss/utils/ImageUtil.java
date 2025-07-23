/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.io.ByteArrayOutputStream;
/*    */ import java.io.File;
/*    */ import java.io.FileOutputStream;
/*    */ import java.io.InputStream;
/*    */ import java.net.HttpURLConnection;
/*    */ import java.net.URL;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class ImageUtil
/*    */ {
/*    */   public static void writeImageToDisk(byte[] data, String fileName) {
/*    */     try {
/* 27 */       File file = new File(fileName);
/* 28 */       File fileParent = file.getParentFile();
/* 29 */       if (!fileParent.exists()) {
/* 30 */         fileParent.mkdirs();
/* 31 */         file.createNewFile();
/*    */       } 
/* 33 */       FileOutputStream fops = new FileOutputStream(file);
/* 34 */       fops.write(data);
/* 35 */       fops.flush();
/* 36 */       fops.close();
/* 37 */     } catch (Exception e) {
/* 38 */       e.printStackTrace();
/*    */     } 
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static byte[] getImageFromNetByUrl(String strUrl) {
/*    */     try {
/* 50 */       URL url = new URL(strUrl);
/* 51 */       HttpURLConnection conn = (HttpURLConnection)url.openConnection();
/* 52 */       conn.setRequestMethod("GET");
/* 53 */       conn.setConnectTimeout(5000);
/* 54 */       InputStream inStream = conn.getInputStream();
/* 55 */       byte[] btData = readInputStream(inStream);
/* 56 */       return btData;
/* 57 */     } catch (Exception e) {
/* 58 */       e.printStackTrace();
/*    */       
/* 60 */       return null;
/*    */     } 
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static byte[] readInputStream(InputStream inStream) throws Exception {
/* 71 */     ByteArrayOutputStream outStream = new ByteArrayOutputStream();
/* 72 */     byte[] buffer = new byte[1024];
/* 73 */     int len = 0;
/* 74 */     while ((len = inStream.read(buffer)) != -1) {
/* 75 */       outStream.write(buffer, 0, len);
/*    */     }
/* 77 */     inStream.close();
/* 78 */     return outStream.toByteArray();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\ImageUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */