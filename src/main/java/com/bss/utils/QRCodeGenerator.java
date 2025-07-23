/*    */ package com.bss.utils;
/*    */ 
/*    */ import com.google.zxing.BarcodeFormat;
/*    */ import com.google.zxing.EncodeHintType;
/*    */ import com.google.zxing.WriterException;
/*    */ import com.google.zxing.client.j2se.MatrixToImageWriter;
/*    */ import com.google.zxing.common.BitMatrix;
/*    */ import com.google.zxing.qrcode.QRCodeWriter;
/*    */ import java.io.ByteArrayOutputStream;
/*    */ import java.io.IOException;
/*    */ import java.util.HashMap;
/*    */ import java.util.Map;
/*    */ 
/*    */ 
/*    */ public class QRCodeGenerator
/*    */ {
/*    */   private static final String CHARSET = "UTF-8";
/*    */   private static final int WIDTH = 300;
/*    */   private static final int HEIGHT = 300;
/*    */   
/*    */   public static byte[] getQRCodeImage(String text) throws WriterException, IOException {
/* 22 */     Map<EncodeHintType, Object> hints = new HashMap<>();
/* 23 */     hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
/* 24 */     hints.put(EncodeHintType.MARGIN, Integer.valueOf(1));
/*    */     
/* 26 */     QRCodeWriter qrCodeWriter = new QRCodeWriter();
/* 27 */     BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 300, 300, hints);
/*    */     
/* 29 */     ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
/* 30 */     MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
/* 31 */     return pngOutputStream.toByteArray();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\QRCodeGenerator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */