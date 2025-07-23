/*    */ package com.bss.sdk.utils;
/*    */ 
/*    */

/*    */ import java.io.File;
/*    */ import java.io.FileInputStream;
/*    */ import java.io.InputStream;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ 
/*    */ 
/*    */ public class FileUtils
/*    */ {
/* 13 */   public static final Logger logger = LoggerFactory.getLogger(com.bss.sdk.utils.FileUtils.class);
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static InputStream loadFile(String fileName) {
/* 19 */     if (StringUtils.isNotBlank(fileName)) {
/* 20 */       return absolutePathStart(fileName) ? loadFromAbsoluteFile(fileName) : loadFromClasspathFile(fileName);
/*    */     }
/* 22 */     return null;
/*    */   }
/*    */ 
/*    */   
/*    */   private static InputStream loadFromAbsoluteFile(String fileName) {
/*    */     try {
/* 28 */       File f = new File(fileName);
/* 29 */       return !f.exists() ? null : new FileInputStream(f);
/* 30 */     } catch (Throwable var3) {
/* 31 */       logger.warn("load file[" + fileName + "] fail", var3);
/* 32 */       return null;
/*    */     } 
/*    */   }
/*    */   
/*    */   private static boolean absolutePathStart(String path) {
/* 37 */     File[] files = File.listRoots();
/* 38 */     File[] var2 = files;
/* 39 */     int var3 = files.length;
/*    */     
/* 41 */     for (int var4 = 0; var4 < var3; var4++) {
/* 42 */       File file = var2[var4];
/* 43 */       if (path.startsWith(file.getPath())) {
/* 44 */         return true;
/*    */       }
/*    */     } 
/*    */     
/* 48 */     return false;
/*    */   }
/*    */ 
/*    */   
/*    */   private static InputStream loadFromClasspathFile(String fileName) {
/*    */     try {
/* 54 */       return com.bss.sdk.utils.FileUtils.class.getClassLoader().getResourceAsStream(fileName);
/* 55 */     } catch (Throwable var2) {
/* 56 */       logger.warn("load file[" + fileName + "] fail", var2);
/* 57 */       return null;
/*    */     } 
/*    */   }
/*    */   
/*    */   private static InputStream loadFromRelativeFile(String fileName) {
/* 62 */     String userDir = System.getProperty("user.dir");
/* 63 */     String realFilePath = addSeparator(userDir) + fileName;
/* 64 */     return loadFromAbsoluteFile(realFilePath);
/*    */   }
/*    */   
/*    */   private static String addSeparator(String dir) {
/* 68 */     if (!dir.endsWith(File.separator)) {
/* 69 */       dir = dir + File.separator;
/*    */     }
/*    */     
/* 72 */     return dir;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\FileUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */