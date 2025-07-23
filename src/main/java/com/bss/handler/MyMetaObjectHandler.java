/*    */ package com.bss.handler;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.handlers.MetaObjectHandler;
/*    */ import java.util.Date;
/*    */ import org.apache.ibatis.reflection.MetaObject;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.stereotype.Component;
/*    */ 
/*    */ 
/*    */ @Component
/*    */ public class MyMetaObjectHandler
/*    */   implements MetaObjectHandler
/*    */ {
/* 15 */   private static final Logger log = LoggerFactory.getLogger(com.bss.handler.MyMetaObjectHandler.class);
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public void insertFill(MetaObject metaObject) {
/* 21 */     strictInsertFill(metaObject, "createTime", Date.class, new Date());
/*    */   }
/*    */ 
/*    */ 
/*    */   
/*    */   public void updateFill(MetaObject metaObject) {
/* 27 */     strictUpdateFill(metaObject, "updateTime", Date.class, new Date());
/* 28 */     setFieldValByName("updateTime", new Date(), metaObject);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\handler\MyMetaObjectHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */