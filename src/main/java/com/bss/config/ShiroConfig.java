package com.bss.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.bss.listener.MyShiroSessionListener;
import com.bss.shiro.CustomRealm;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig
{
    @Bean(name = {"shiroFilter"})
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/login.html");
        shiroFilterFactoryBean.setUnauthorizedUrl("/");

        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();

        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/fonts/**", "anon");
        filterChainDefinitionMap.put("/images/**", "anon");
        filterChainDefinitionMap.put("/js/**", "anon");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/login.html", "anon");
        filterChainDefinitionMap.put("/index", "authc");
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/api/send_code", "anon");
        filterChainDefinitionMap.put("/api/login_phone", "anon");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    @Bean(name = {"sessionManager"})
    public DefaultWebSessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setGlobalSessionTimeout(360000000L);
        sessionManager.setSessionListeners(Collections.singletonList(new MyShiroSessionListener()));
        return sessionManager;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager defaultSecurityManager = new DefaultWebSecurityManager();
        defaultSecurityManager.setRealm((Realm)shiroRealm());
        defaultSecurityManager.setSessionManager((SessionManager)sessionManager());
        return (SecurityManager)defaultSecurityManager;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(3);
        credentialsMatcher.setStoredCredentialsHexEncoded(true);
        return credentialsMatcher;
    }

    @Bean
    public CustomRealm shiroRealm() {
        CustomRealm shiroRealm = new CustomRealm();
        shiroRealm.setCredentialsMatcher((CredentialsMatcher)hashedCredentialsMatcher());
        return shiroRealm;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}