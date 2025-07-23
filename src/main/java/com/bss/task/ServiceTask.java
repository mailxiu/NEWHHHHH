/*    */ package com.bss.task;
/*    */ import com.alibaba.fastjson.JSONObject;
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bss.entity.AppletConfig;
/*    */ import com.bss.service.impl.AppletConfigServiceImpl;
/*    */ import java.util.List;
/*    */ import javax.annotation.Resource;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.http.HttpEntity;
/*    */ import org.springframework.http.HttpHeaders;
/*    */ import org.springframework.http.HttpMethod;
/*    */ import org.springframework.http.MediaType;
/*    */ import org.springframework.http.ResponseEntity;
/*    */ import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
/*    */ import org.springframework.util.MultiValueMap;
/*    */ import org.springframework.web.client.RestTemplate;
/*    */ 
/*    */ @Component
/*    */ public class ServiceTask {
/* 21 */   private static final Logger log = LoggerFactory.getLogger(com.bss.task.ServiceTask.class);
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @Resource
/*    */   private AppletConfigServiceImpl appletConfigService;
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @Scheduled(cron = "0 0/10 * * * ?")
/*    */   public void getAccessTokenAuto() {
/* 34 */     log.info("===执行小程序Token刷新任务===");
/*    */     
/* 36 */     List<AppletConfig> list = this.appletConfigService.list((Wrapper)new QueryWrapper());
/*    */     
/* 38 */     for (int i = 0; i < list.size(); i++) {
/*    */       
/* 40 */       AppletConfig applet = list.get(i);
/*    */       
/* 42 */       String url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + applet.getAppId() + "&secret=" + applet.getSecret();
/*    */       
/* 44 */       MediaType type = MediaType.parseMediaType("application/x-www-form-urlencoded; charset=UTF-8");
/* 45 */       HttpHeaders headers = new HttpHeaders();
/* 46 */       headers.setContentType(type);
/*    */       
/* 48 */       HttpEntity<String> requestEntity = new HttpEntity(null, (MultiValueMap)headers);
/*    */       
/* 50 */       RestTemplate restTemplate = new RestTemplate();
/*    */       
/* 52 */       ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class, new Object[0]);
/*    */       
/* 54 */       System.out.println((String)responseEntity.getBody());
/*    */       
/* 56 */       JSONObject data = JSONObject.parseObject((String)responseEntity.getBody());
/*    */       
/* 58 */       applet.setAccessToken(data.getString("access_token"));
/*    */       
/* 60 */       this.appletConfigService.saveOrUpdate(applet);
/*    */     } 
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\task\ServiceTask.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */