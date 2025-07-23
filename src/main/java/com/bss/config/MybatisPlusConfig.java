/*    */ package com.bss.config;
/*    */ 
/*    */ import com.baomidou.mybatisplus.annotation.DbType;
/*    */ import com.baomidou.mybatisplus.autoconfigure.MybatisPlusProperties;
/*    */ import com.baomidou.mybatisplus.autoconfigure.MybatisPlusPropertiesCustomizer;
/*    */ import com.baomidou.mybatisplus.core.MybatisConfiguration;
/*    */ import com.baomidou.mybatisplus.core.config.GlobalConfig;
/*    */ import com.baomidou.mybatisplus.core.handlers.MybatisEnumTypeHandler;
/*    */ import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
/*    */ import com.baomidou.mybatisplus.extension.plugins.inner.InnerInterceptor;
/*    */ import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
/*    */ import org.springframework.context.annotation.Bean;
/*    */ import org.springframework.context.annotation.Configuration;
/*    */ 
/*    */ 
/*    */ 
/*    */ @Configuration
/*    */ public class MybatisPlusConfig
/*    */ {
/*    */   @Bean
/*    */   public MybatisPlusInterceptor mybatisPlusInterceptor() {
/* 22 */     MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
/* 23 */     interceptor.addInnerInterceptor((InnerInterceptor)new PaginationInnerInterceptor(DbType.MYSQL));
/* 24 */     return interceptor;
/*    */   }
/*    */   
/*    */   @Bean
/*    */   public MybatisPlusPropertiesCustomizer mybatisPlusPropertiesCustomizer() {
/* 29 */     return properties -> {
/*    */         GlobalConfig globalConfig = properties.getGlobalConfig();
/*    */         globalConfig.setBanner(false);
/*    */         MybatisConfiguration configuration = new MybatisConfiguration();
/*    */         configuration.setDefaultEnumTypeHandler(MybatisEnumTypeHandler.class);
/*    */         properties.setConfiguration(configuration);
/*    */       };
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\config\MybatisPlusConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */