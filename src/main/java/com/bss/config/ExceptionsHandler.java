/*    */ package com.bss.config;
/*    */ 
/*    */ import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.service.impl.ExceptionLogServiceImpl;
/*    */ import javax.annotation.Resource;
/*    */ import org.apache.shiro.authz.UnauthorizedException;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.web.bind.annotation.ExceptionHandler;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class ExceptionsHandler
/*    */ {
/* 18 */   private static final Logger log = LoggerFactory.getLogger(com.bss.config.ExceptionsHandler.class);
/*    */ 
/*    */   
/*    */   @Resource
/*    */   ExceptionLogServiceImpl exceptionLogService;
/*    */ 
/*    */ 
/*    */   
/*    */   @ExceptionHandler({UnauthorizedException.class})
/*    */   public R unauthorizedException(UnauthorizedException ex) {
/* 28 */     log.error("缺少权限：{} ", ex.getMessage(), ex);
/*    */     
/* 30 */     return R.ok("").setCode(101L).setMsg(ex.getMessage());
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\config\ExceptionsHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */