/*    */ package com.bss.sdk.utils;
/*    */ 
/*    */ import com.bss.sdk.exception.SandPayException;
/*    */ import java.io.BufferedReader;
/*    */ import java.io.IOException;
/*    */ import java.io.InputStreamReader;
/*    */ import java.io.PrintWriter;
/*    */ import java.net.URL;
/*    */ import java.net.URLConnection;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ 
/*    */ 
/*    */ public class HttpClientUtils
/*    */ {
/* 16 */   public static final Logger logger = LoggerFactory.getLogger(com.bss.sdk.utils.HttpClientUtils.class);
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String sendPost(String url, String param, int connectTimeout, int readTimeout) {
/* 22 */     PrintWriter out = null;
/* 23 */     BufferedReader in = null;
/*    */     
/*    */     try {
/* 26 */       URL realUrl = new URL(url);
/* 27 */       URLConnection conn = realUrl.openConnection();
/* 28 */       conn.setRequestProperty("Content-Type", "application/json");
/* 29 */       conn.setRequestProperty("accept", "*/*");
/* 30 */       conn.setRequestProperty("connection", "Keep-Alive");
/* 31 */       conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
/* 32 */       conn.setDoOutput(true);
/* 33 */       conn.setDoInput(true);
/* 34 */       conn.setConnectTimeout(connectTimeout);
/* 35 */       conn.setReadTimeout(readTimeout);
/* 36 */       out = new PrintWriter(conn.getOutputStream());
/* 37 */       out.print(param);
/* 38 */       out.flush();
/* 39 */       in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
/* 40 */       StringBuilder sb = new StringBuilder();
/* 41 */       String line = null;
/*    */       
/* 43 */       while ((line = in.readLine()) != null) {
/* 44 */         sb.append(line);
/*    */       }
/*    */       
/* 47 */       String var10 = sb.toString();
/* 48 */       return var10;
/* 49 */     } catch (Exception var19) {
/* 50 */       throw new SandPayException("请求服务器失败，url:" + url + " err：" + var19.getMessage(), var19);
/*    */     } finally {
/*    */       try {
/* 53 */         if (out != null) {
/* 54 */           out.close();
/*    */         }
/*    */         
/* 57 */         if (in != null) {
/* 58 */           in.close();
/*    */         }
/* 60 */       } catch (IOException var18) {
/* 61 */         logger.error("发送POST方法的请求，关闭流异常：", var18);
/*    */       } 
/*    */     } 
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\HttpClientUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */