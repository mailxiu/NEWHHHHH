/*    */ package com.bss.component;
/*    */ 
/*    */ import java.io.IOException;
/*    */ import java.util.concurrent.ConcurrentHashMap;
/*    */ import org.apache.shiro.session.Session;
/*    */ import org.springframework.stereotype.Component;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Component
/*    */ public class MyShiroSessionManager
/*    */ {
/* 17 */   private static final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
/*    */   
/*    */   public static void addSession(String sessionId, Session session) {
/* 20 */     sessions.put(sessionId, session);
/*    */   }
/*    */   
/*    */   public static void removeSession(String sessionId) {
/* 24 */     sessions.remove(sessionId);
/*    */   }
/*    */ 
/*    */   
/*    */   public static Boolean searchMessage(String sessionId) throws IOException {
/* 29 */     Session session = sessions.get(sessionId);
/* 30 */     if (session != null) {
/* 31 */       return Boolean.valueOf(true);
/*    */     }
/* 33 */     return Boolean.valueOf(false);
/*    */   }
/*    */ 
/*    */ 
/*    */   
/*    */   public static void closeMessage(String sessionId) throws IOException {
/* 39 */     Session session = sessions.get(sessionId);
/* 40 */     if (session != null) {
/* 41 */       session.stop();
/* 42 */       sessions.remove(sessionId);
/*    */     } 
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\component\MyShiroSessionManager.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */