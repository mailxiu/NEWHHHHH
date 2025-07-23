/*    */ package com.bss.listener;
/*    */ 
/*    */ import com.bss.component.MyShiroSessionManager;
/*    */ import java.io.IOException;
/*    */ import org.apache.shiro.session.Session;
/*    */ import org.apache.shiro.session.SessionListener;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.stereotype.Component;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Component
/*    */ public class MyShiroSessionListener
/*    */   implements SessionListener
/*    */ {
/* 20 */   private static final Logger logger = LoggerFactory.getLogger(com.bss.listener.MyShiroSessionListener.class);
/*    */ 
/*    */   
/*    */   public void onStart(Session session) {
/* 24 */     logger.info("Shiro Session 创建: {}", session.getId());
/* 25 */     MyShiroSessionManager.addSession(session.getId().toString(), session);
/*    */   }
/*    */ 
/*    */ 
/*    */   
/*    */   public void onStop(Session session) {
/* 31 */     logger.info("Shiro Session 关闭: {}", session.getId());
/*    */     
/* 33 */     MyShiroSessionManager.removeSession(session.getId().toString());
/*    */   }
/*    */ 
/*    */ 
/*    */   
/*    */   public void onExpiration(Session session) {
/* 39 */     logger.info("Shiro Session 过期: {}", session.getId());
/*    */     
/*    */     try {
/* 42 */       MyShiroSessionManager.closeMessage(session.getId().toString());
/* 43 */     } catch (IOException e) {
/* 44 */       throw new RuntimeException(e);
/*    */     } 
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\listener\MyShiroSessionListener.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */