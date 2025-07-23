/*    */ package com.bss.service.impl;
/*    */ 
/*    */ import cn.hutool.core.util.RandomUtil;
/*    */ import com.alibaba.fastjson.JSONObject;
/*    */ import com.aliyuncs.CommonRequest;
/*    */ import com.aliyuncs.CommonResponse;
/*    */ import com.aliyuncs.DefaultAcsClient;
/*    */ import com.aliyuncs.exceptions.ClientException;
/*    */ import com.aliyuncs.exceptions.ServerException;
/*    */ import com.aliyuncs.http.MethodType;
/*    */ import com.aliyuncs.profile.DefaultProfile;
/*    */ import com.aliyuncs.profile.IClientProfile;
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.bss.entity.MessageConfig;
/*    */
/*    */ import com.bss.utils.R;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.stereotype.Service;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Service
/*    */ public class ShortMessagesServiceImpl
/*    */ {
/*    */   @Resource
/*    */   private MessageConfigServiceImpl messageConfigService;
/*    */   
/*    */   public R verification_code(String phone) {
/* 38 */     MessageConfig messageConfig = (MessageConfig)this.messageConfigService.getOne((Wrapper)new QueryWrapper());
/*    */ 
/*    */     
/* 41 */     String code = RandomUtil.randomNumbers(6);
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */     
/* 47 */     DefaultProfile profile = DefaultProfile.getProfile(messageConfig.getRegionId(), messageConfig.getAccessKeyId(), messageConfig.getAccessKeySecret());
/* 48 */     DefaultAcsClient defaultAcsClient = new DefaultAcsClient((IClientProfile)profile);
/*    */     
/* 50 */     CommonRequest request = new CommonRequest();
/* 51 */     request.setMethod(MethodType.POST);
/* 52 */     request.setDomain("dysmsapi.aliyuncs.com");
/* 53 */     request.setVersion("2017-05-25");
/* 54 */     request.setAction("SendSms");
/* 55 */     request.putQueryParameter("RegionId", messageConfig.getRegionId());
/* 56 */     request.putQueryParameter("PhoneNumbers", phone);
/* 57 */     request.putQueryParameter("SignName", messageConfig.getSignName());
/* 58 */     request.putQueryParameter("TemplateCode", messageConfig.getTemplateCode());
/* 59 */     request.putQueryParameter("TemplateParam", "{\"code\":\"" + code + "\"}");
/*    */ 
/*    */     
/* 62 */     JSONObject data = new JSONObject();
/*    */ 
/*    */     
/*    */     try {
/* 66 */       CommonResponse response = defaultAcsClient.getCommonResponse(request);
/* 67 */       System.out.println(response.getData());
/*    */       
/* 69 */       data = JSONObject.parseObject(response.getData().toString());
/*    */       
/* 71 */       if (!data.getString("Message").equals("OK")) {
/* 72 */         return R.fail(data.getString("Message"));
/*    */       }
/* 74 */       return R.success(code);
/*    */     
/*    */     }
/* 77 */     catch (ServerException e) {
/* 78 */       e.printStackTrace();
/* 79 */     } catch (ClientException e) {
/* 80 */       e.printStackTrace();
/*    */     } 
/*    */     
/* 83 */     return R.success(code);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\ShortMessagesServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */