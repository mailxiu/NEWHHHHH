/*    */ package com.bss.utils;
/*    */ 
/*    */ import com.google.zxing.BarcodeFormat;
/*    */ import com.google.zxing.EncodeHintType;
/*    */ import com.google.zxing.MultiFormatWriter;
/*    */ import com.google.zxing.common.BitMatrix;
/*    */ import java.awt.Color;
/*    */ import java.awt.image.BufferedImage;
/*    */ import java.io.ByteArrayOutputStream;
/*    */ import java.util.HashMap;
/*    */ import java.util.Map;
/*    */ import javax.imageio.ImageIO;
/*    */ 
/*    */ 
/*    */ 
/*    */ public class QRCodeGeneratorWithColor
/*    */ {
/*    */   private static final String CHARSET = "UTF-8";
/*    */   private static final int WIDTH = 350;
/*    */   private static final int HEIGHT = 350;
/*    */   
/*    */   public static byte[] generateColoredQRCodeImage(String text, Color foreColor, Color backColor) throws Exception {
/* 23 */     Map<EncodeHintType, Object> hintMap = new HashMap<>();
/* 24 */     hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");
/* 25 */     hintMap.put(EncodeHintType.MARGIN, Integer.valueOf(1));
/*    */     
/* 27 */     BitMatrix bitMatrix = (new MultiFormatWriter()).encode(text, BarcodeFormat.QR_CODE, 350, 350, hintMap);
/*    */ 
/*    */     
/* 30 */     int matrixWidth = bitMatrix.getWidth();
/*    */     
/* 32 */     BufferedImage image = new BufferedImage(matrixWidth, matrixWidth, 1);
/*    */     
/* 34 */     for (int x = 0; x < matrixWidth; x++) {
/* 35 */       for (int y = 0; y < matrixWidth; y++) {
/* 36 */         if (bitMatrix.get(x, y)) {
/* 37 */           image.setRGB(x, y, foreColor.getRGB());
/*    */         } else {
/* 39 */           image.setRGB(x, y, backColor.getRGB());
/*    */         } 
/*    */       } 
/*    */     } 
/*    */     
/* 44 */     ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
/*    */     
/* 46 */     ImageIO.write(image, "PNG", pngOutputStream);
/* 47 */     pngOutputStream.flush();
/*    */     
/* 49 */     return pngOutputStream.toByteArray();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\QRCodeGeneratorWithColor.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */