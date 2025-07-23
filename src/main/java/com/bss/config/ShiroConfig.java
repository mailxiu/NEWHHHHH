/*     */ package com.bss.config;
/*     */ 
/*     */ import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
/*     */ import com.bss.listener.MyShiroSessionListener;
/*     */ import com.bss.shiro.CustomRealm;
/*     */ import java.util.Collections;
/*     */ import java.util.LinkedHashMap;
/*     */ import java.util.Map;
/*     */ import org.apache.shiro.authc.credential.CredentialsMatcher;
/*     */ import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
/*     */ import org.apache.shiro.mgt.SecurityManager;
/*     */ import org.apache.shiro.realm.Realm;
/*     */ import org.apache.shiro.session.mgt.SessionManager;
/*     */ import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
/*     */ import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
/*     */ import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
/*     */ import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
/*     */ import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
/*     */ import org.springframework.context.annotation.Bean;
/*     */ import org.springframework.context.annotation.Configuration;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ @Configuration
/*     */ public class ShiroConfig
/*     */ {
/*     */   @Bean(name = {"shiroFilter"})
/*     */   public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
/*  38 */     ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
/*  39 */     shiroFilterFactoryBean.setSecurityManager(securityManager);
/*  40 */     shiroFilterFactoryBean.setLoginUrl("/login.html");
/*  41 */     shiroFilterFactoryBean.setUnauthorizedUrl("/");
/*     */     
/*  43 */     Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
/*     */     
/*  45 */     filterChainDefinitionMap.put("/static/**", "anon");
/*  46 */     filterChainDefinitionMap.put("/css/**", "anon");
/*  47 */     filterChainDefinitionMap.put("/fonts/**", "anon");
/*  48 */     filterChainDefinitionMap.put("/images/**", "anon");
/*  49 */     filterChainDefinitionMap.put("/js/**", "anon");
/*  50 */     filterChainDefinitionMap.put("/login", "anon");
/*  51 */     filterChainDefinitionMap.put("/login.html", "anon");
/*  52 */     filterChainDefinitionMap.put("/index", "authc");
/*  53 */     filterChainDefinitionMap.put("/logout", "logout");
/*  54 */     filterChainDefinitionMap.put("/api/send_code", "anon");
/*  55 */     filterChainDefinitionMap.put("/api/login_phone", "anon");
/*  56 */     filterChainDefinitionMap.put("/**", "anon");
/*     */ 
/*     */ 
/*     */     
/*  60 */     shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
/*  61 */     return shiroFilterFactoryBean;
/*     */   }
/*     */ 
/*     */   
/*     */   @Bean
/*     */   public ShiroDialect shiroDialect() {
/*  67 */     return new ShiroDialect();
/*     */   }
/*     */ 
/*     */   
/*     */   @Bean(name = {"sessionManager"})
/*     */   public DefaultWebSessionManager sessionManager() {
/*  73 */     DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
/*     */     
/*  75 */     sessionManager.setGlobalSessionTimeout(360000000L);
/*     */ 
/*     */     
/*  78 */     sessionManager.setSessionListeners(Collections.singletonList(new MyShiroSessionListener()));
/*     */     
/*  80 */     return sessionManager;
/*     */   }
/*     */   
/*     */   @Bean
/*     */   public SecurityManager securityManager() {
/*  85 */     DefaultWebSecurityManager defaultSecurityManager = new DefaultWebSecurityManager();
/*  86 */     defaultSecurityManager.setRealm((Realm)shiroRealm());
/*  87 */     defaultSecurityManager.setSessionManager((SessionManager)sessionManager());
/*  88 */     return (SecurityManager)defaultSecurityManager;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Bean
/*     */   public HashedCredentialsMatcher hashedCredentialsMatcher() {
/* 100 */     HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
/*     */     
/* 102 */     credentialsMatcher.setHashAlgorithmName("md5");
/*     */     
/* 104 */     credentialsMatcher.setHashIterations(3);
/*     */     
/* 106 */     credentialsMatcher.setStoredCredentialsHexEncoded(true);
/* 107 */     return credentialsMatcher;
/*     */   }
/*     */   
/*     */   @Bean
/*     */   public CustomRealm shiroRealm() {
/* 112 */     CustomRealm shiroRealm = new CustomRealm();
/* 113 */     shiroRealm.setCredentialsMatcher((CredentialsMatcher)hashedCredentialsMatcher());
/*     */     
/* 115 */     return shiroRealm;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Bean
/*     */   public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
/* 125 */     DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
/* 126 */     advisorAutoProxyCreator.setProxyTargetClass(true);
/* 127 */     return advisorAutoProxyCreator;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Bean
/*     */   public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
/* 137 */     AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
/* 138 */     authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
/* 139 */     return authorizationAttributeSourceAdvisor;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\config\ShiroConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */