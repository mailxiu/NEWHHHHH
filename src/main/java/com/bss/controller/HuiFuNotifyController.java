/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.OrderServiceImpl;
/*     */ import com.huifu.bspay.sdk.opps.core.utils.RsaUtils;
/*     */ import java.util.Enumeration;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpServletRequest;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.ResponseBody;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"/huiFuPay"})
/*     */ public class HuiFuNotifyController
/*     */ {
/*  26 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.HuiFuNotifyController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public static final String DEMO_RSA_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJAKwd9m7ZeTJAUnRb44I3LcmBzspqtXqCULL+7LoQirD1+X1nK+i7UoOadZ0ev64B/60clkftU8PU1tnCyPCABUlLl6QGCRDl+dvVPPiCHtJE37DbQQbUh6acrW+lo3HlM0SNHVH05grrun5EuWLYFusS+UjNDA0gbjaygdK3ONxrfvo4qrB6mSAoxLkqya/rU/7TYqa5o7BlhkTmtbcl8shzgY0sqtBMmVeE0cSSmaWN8crTR5F36sIBcQ50RPpRT4KEWyP/MMM65UhHTT80U7pnxZKQD1+s5rmHIwc9px/l2mMGQkrvWvrCNobfFJ5o1Z0r4NqQa8SG/jSTAKDQIDAQAB";
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/payNotify"})
/*     */   @ResponseBody
/*     */   public String newNotify(HttpServletRequest request) {
/*  49 */     System.out.println("收到汇付支付回调");
/*     */     
/*  51 */     Enumeration<String> parameterNames = request.getParameterNames();
/*  52 */     while (parameterNames.hasMoreElements()) {
/*  53 */       String paramName = parameterNames.nextElement();
/*  54 */       String[] values = request.getParameterValues(paramName);
/*  55 */       for (String value : values) {
/*  56 */         System.out.println("Parameter: " + paramName + ", Value: " + value);
/*     */       }
/*     */     } 
/*     */     
/*  60 */     String data = request.getParameter("resp_data");
/*     */ 
/*     */     
/*     */     try {
/*  64 */       String sign = request.getParameter("sign");
/*     */       
/*  66 */       if (!RsaUtils.verify(data, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJAKwd9m7ZeTJAUnRb44I3LcmBzspqtXqCULL+7LoQirD1+X1nK+i7UoOadZ0ev64B/60clkftU8PU1tnCyPCABUlLl6QGCRDl+dvVPPiCHtJE37DbQQbUh6acrW+lo3HlM0SNHVH05grrun5EuWLYFusS+UjNDA0gbjaygdK3ONxrfvo4qrB6mSAoxLkqya/rU/7TYqa5o7BlhkTmtbcl8shzgY0sqtBMmVeE0cSSmaWN8crTR5F36sIBcQ50RPpRT4KEWyP/MMM65UhHTT80U7pnxZKQD1+s5rmHIwc9px/l2mMGQkrvWvrCNobfFJ5o1Z0r4NqQa8SG/jSTAKDQIDAQAB", sign))
/*     */       {
/*  68 */         return "";
/*     */       }
/*  70 */       JSONObject dataObj = JSON.parseObject(data);
/*  71 */       String subRespCode = dataObj.getString("sub_resp_code");
/*  72 */       String reqSeqId = dataObj.getString("req_seq_id");
/*  73 */       String hfSeqId = dataObj.getString("hf_seq_id");
/*     */       
/*  75 */       if ("00000000".equals(subRespCode)) {
/*     */         
/*  77 */         log.info("处理成功");
/*     */         
/*  79 */         Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", reqSeqId));
/*     */         
/*  81 */         if (order != null && order.getState().equals("待支付")) {
/*     */           
/*  83 */           order.setTransactionId(hfSeqId);
/*     */           
/*  85 */           order.setState("已支付");
/*     */           
/*  87 */           this.orderService.saveOrUpdate(order);
/*     */ 
/*     */           
/*  90 */           log.info("收到支付通知执行会员升级...");
/*     */ 
/*     */           
/*  93 */           R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*     */           
/*  95 */           System.out.println(r);
/*     */         } else {
/*     */           
/*  98 */           System.out.println("未找到支付订单");
/*     */         }
/*     */       
/*     */       }
/*     */       else {
/*     */         
/* 104 */         log.info("处理失败");
/*     */       } 
/* 106 */       return "RECV_ORD_ID_" + reqSeqId;
/* 107 */     } catch (Exception e) {
/* 108 */       log.info("异步回调开始，参数，request={}", data, e);
/*     */ 
/*     */       
/* 111 */       return "";
/*     */     } 
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\HuiFuNotifyController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */