/*    */ package com.bss;
/*    */ 
/*    */ import org.mybatis.spring.annotation.MapperScan;
/*    */ import org.springframework.boot.SpringApplication;
/*    */ import org.springframework.boot.autoconfigure.SpringBootApplication;
/*    */ import org.springframework.scheduling.annotation.EnableScheduling;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @SpringBootApplication
/*    */ @EnableScheduling
/*    */ @MapperScan({"com.bss.mapper"})
/*    */ public class RecoveryApplet
/*    */ {
/*    */   public static void main(String[] args) {
/* 17 */     SpringApplication.run(com.bss.RecoveryApplet.class, args);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\RecoveryApplet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */