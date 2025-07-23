/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.util.Map;
/*    */ import org.springframework.http.HttpEntity;
/*    */ import org.springframework.http.HttpHeaders;
/*    */ import org.springframework.http.MediaType;
/*    */ import org.springframework.http.ResponseEntity;
/*    */ import org.springframework.util.MultiValueMap;
/*    */ import org.springframework.web.client.RestTemplate;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class HttpUtils
/*    */ {
/*    */   public static String putPay(Map<String, Object> map, String url) {
/* 19 */     RestTemplate restTemplate = new RestTemplate();
/* 20 */     HttpHeaders headers = new HttpHeaders();
/* 21 */     headers.setContentType(MediaType.APPLICATION_JSON);
/* 22 */     HttpEntity<Map<String, Object>> request = new HttpEntity(map, (MultiValueMap)headers);
/* 23 */     ResponseEntity<String> entity = restTemplate.postForEntity(url, request, String.class, new Object[0]);
/* 24 */     String body = (String)entity.getBody();
/* 25 */     return body;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\HttpUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */