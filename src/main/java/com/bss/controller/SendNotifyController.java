/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.sdk.SandPayClient;
/*     */ import com.bss.sdk.config.SandPayConfig;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.OrderServiceImpl;
/*     */ import java.util.Map;
/*     */ import java.util.Set;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpServletRequest;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.ResponseBody;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"/sendPay"})
/*     */ public class SendNotifyController
/*     */ {
/*  28 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.SendNotifyController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   private SandPayClient sandPayClient;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/payNotify"})
/*     */   @ResponseBody
/*     */   public String newNotify(HttpServletRequest request) {
/*  56 */     System.out.println("收到森德异步通知");
/*     */ 
/*     */ 
/*     */     
/*  60 */     SandPayConfig config = new SandPayConfig();
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  65 */     config.setAccessMid("6888804128472");
/*     */ 
/*     */     
/*  68 */     config.setEncryptType("AES");
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  73 */     config.setPrivateKeyPath("cert/prod/yunshang.pfx");
/*  74 */     config.setPrivateKeyPassword("123123");
/*  75 */     config.setSandPublicKeyPath("cert/prod/sand_pro.cer");
/*     */ 
/*     */     
/*  78 */     config.setVersion("4.0.0");
/*     */     
/*  80 */     this.sandPayClient = new SandPayClient(config);
/*     */     
/*  82 */     Map<String, String[]> parameterMap = request.getParameterMap();
/*  83 */     if (null == parameterMap || parameterMap.isEmpty()) {
/*  84 */       return null;
/*     */     }
/*  86 */     JSONObject paramJson = new JSONObject();
/*  87 */     Set<Map.Entry<String, String[]>> set = (Set)parameterMap.entrySet();
/*  88 */     for (Map.Entry<String, String[]> entry : set) {
/*  89 */       String[] value = entry.getValue();
/*  90 */       paramJson.put(entry.getKey(), value[0]);
/*     */     } 
/*     */     
/*  93 */     String bizData = paramJson.getString("bizData");
/*  94 */     String sign = paramJson.getString("sign");
/*  95 */     String signType = "SHA256WithRSA";
/*  96 */     String charset = "UTF-8";
/*     */ 
/*     */     
/*  99 */     boolean flag = this.sandPayClient.verifySign(bizData, sign, signType, charset);
/* 100 */     if (!flag) {
/* 101 */       log.error("验签失败");
/* 102 */       return null;
/*     */     } 
/*     */     
/* 105 */     JSONObject bizJson = JSONObject.parseObject(bizData);
/*     */     
/* 107 */     if (bizJson.getString("orderStatus").equals("success")) {
/*     */       
/* 109 */       String outOrderNo = bizJson.getString("outOrderNo");
/*     */       
/* 111 */       String sandSerialNo = bizJson.getString("sandSerialNo");
/*     */       
/* 113 */       Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", outOrderNo));
/*     */       
/* 115 */       if (order != null) {
/*     */         
/* 117 */         order.setTransactionId(sandSerialNo);
/*     */         
/* 119 */         order.setState("已支付");
/*     */         
/* 121 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 124 */         log.info("收到支付通知执行会员升级...");
/*     */ 
/*     */         
/* 127 */         R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*     */         
/* 129 */         System.out.println(r);
/*     */       } else {
/*     */         
/* 132 */         System.out.println("未找到支付订单");
/*     */       } 
/*     */     } 
/*     */ 
/*     */     
/* 137 */     log.info("验签成功，报文: {}", bizData);
/*     */     
/* 139 */     return "respCode=000000";
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\SendNotifyController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */