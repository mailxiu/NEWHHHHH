/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.awt.image.BufferedImage;
/*    */ import java.io.ByteArrayInputStream;
/*    */ import java.io.IOException;
/*    */ import javax.imageio.ImageIO;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class ImageConverter
/*    */ {
/*    */   public static BufferedImage byteToBufferedImage(byte[] imageBytes) throws IOException {
/* 18 */     ByteArrayInputStream bis = new ByteArrayInputStream(imageBytes);
/* 19 */     BufferedImage bufferedImage = ImageIO.read(bis);
/* 20 */     if (bufferedImage == null) {
/* 21 */       throw new IOException("Failed to convert byte array to BufferedImage. Check the input data.");
/*    */     }
/* 23 */     return bufferedImage;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\ImageConverter.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */