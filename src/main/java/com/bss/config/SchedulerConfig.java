/*    */ package com.bss.config;
/*    */ 
/*    */ import org.springframework.context.annotation.Bean;
/*    */ import org.springframework.context.annotation.Configuration;
/*    */ import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Configuration
/*    */ public class SchedulerConfig
/*    */ {
/*    */   @Bean
/*    */   public ThreadPoolTaskScheduler taskScheduler() {
/* 18 */     ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
/* 19 */     taskScheduler.setPoolSize(10);
/* 20 */     taskScheduler.setThreadNamePrefix("CustomTaskScheduler-");
/* 21 */     return taskScheduler;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\config\SchedulerConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */