/*     */ package com.bss.service.impl;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bss.enmus.PaymentEnum;
/*     */ import com.bss.enmus.SandPayMethodEnum;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.sdk.SandPayClient;
/*     */ import com.bss.sdk.config.SandPayConfig;
/*     */
/*     */ import com.bss.utils.R;
/*     */ import java.text.SimpleDateFormat;
/*     */ import javax.annotation.Resource;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.stereotype.Service;
/*     */ 
/*     */ @Service
/*     */ public class SandPayServiceImpl {
/*  19 */   private static final Logger log = LoggerFactory.getLogger(com.bss.service.impl.SandPayServiceImpl.class);
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
/*     */   public static final String SANDPAY_BASE_URL = "https://openapi.sandpay.com.cn";
/*     */ 
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
/*     */   
/*     */   public R testReceiptsOrderCreate(String oid) {
/*  46 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */ 
/*     */     
/*  49 */     SandPayConfig config = new SandPayConfig();
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  54 */     config.setAccessMid("6888804128472");
/*     */ 
/*     */ 
/*     */     
/*  58 */     config.setEncryptType("AES");
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  63 */     config.setPrivateKeyPath("cert/prod/yunshang.pfx");
/*  64 */     config.setPrivateKeyPassword("123123");
/*  65 */     config.setSandPublicKeyPath("cert/prod/sand_pro.cer");
/*     */ 
/*     */ 
/*     */     
/*  69 */     config.setVersion("4.0.0");
/*     */     
/*  71 */     this.sandPayClient = new SandPayClient(config);
/*     */ 
/*     */     
/*  74 */     JSONObject bizData = new JSONObject();
/*     */     
/*  76 */     bizData.put("mid", "6888804128472");
/*  77 */     bizData.put("marketProduct", "CSDB");
/*     */     
/*  79 */     bizData.put("outOrderNo", order.getOid());
/*     */     
/*  81 */     bizData.put("amount", order.getMoney());
/*     */     
/*  83 */     bizData.put("outReqTime", (new SimpleDateFormat("yyyyMMddHHmmss")).format(Long.valueOf(System.currentTimeMillis())));
/*  84 */     bizData.put("description", "技术服务费");
/*     */ 
/*     */ 
/*     */     
/*  88 */     if (order.getPaymentType().equals(PaymentEnum.SendPay)) {
/*  89 */       buildFASTPAYSANDH5(bizData, order.getUid());
/*  90 */     } else if (order.getPaymentType().equals(PaymentEnum.SendYLPay)) {
/*  91 */       buildCUPPAYQR(bizData);
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/*  98 */     JSONObject sdExtra = new JSONObject();
/*  99 */     bizData.put("sdExtra", sdExtra);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 105 */     JSONObject reqReserved = new JSONObject();
/* 106 */     reqReserved.put("reqMemo", "请求方保留域");
/* 107 */     bizData.put("reqReserved", reqReserved);
/*     */ 
/*     */ 
/*     */     
/* 111 */     String url = String.format("https://openapi.sandpay.com.cn"
/* 112 */         .concat("/%s"), new Object[] { SandPayMethodEnum.RECEIPTS_TRANS_ORDER_CREATE.getMethod() });
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 118 */     JSONObject responseJson = this.sandPayClient.execute(url, bizData);
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 123 */     if (responseJson.getString("resultStatus").equals("accept")) {
/*     */       
/* 125 */       JSONObject credential = responseJson.getJSONObject("credential");
/*     */       
/* 127 */       if (order.getPaymentType().equals(PaymentEnum.SendPay))
/* 128 */         return R.success(credential.getString("cashierUrl")); 
/* 129 */       if (order.getPaymentType().equals(PaymentEnum.SendYLPay)) {
/* 130 */         return R.success(credential.getString("qrCode"));
/*     */       }
/* 132 */       return R.fail("未知支付类型");
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 137 */     String errorDesc = responseJson.getString("errorDesc");
/*     */     
/* 139 */     return R.fail("支付下单失败：," + errorDesc);
/*     */   }
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
/*     */   
/*     */   public void buildFASTPAYSANDH5(JSONObject bizData, String userId) {
/* 155 */     JSONObject payerInfo = new JSONObject();
/* 156 */     payerInfo.put("userId", userId);
/* 157 */     payerInfo.put("frontUrl", "https://hs.mailxiu.com/open/transfer");
/*     */     
/* 159 */     bizData.put("payerInfo", payerInfo);
/*     */ 
/*     */     
/* 162 */     bizData.put("notifyUrl", "https://hs.mailxiu.com/sendPay/payNotify");
/*     */     
/* 164 */     bizData.put("goodsClass", "01");
/* 165 */     bizData.put("payType", "FASTPAY");
/* 166 */     bizData.put("payMode", "SANDH5");
/*     */   }
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
/*     */   public void buildCUPPAYQR(JSONObject bizData) {
/* 179 */     JSONObject payerInfo = new JSONObject();
/*     */     
/* 181 */     payerInfo.put("payTypeList", "CUPPAY");
/*     */     
/* 183 */     bizData.put("payerInfo", payerInfo);
/*     */ 
/*     */ 
/*     */     
/* 187 */     bizData.put("notifyUrl", "https://hs.mailxiu.com/sendPay/payNotify");
/*     */     
/* 189 */     bizData.put("goodsClass", "01");
/* 190 */     bizData.put("payType", "CUPPAY");
/* 191 */     bizData.put("payMode", "QR");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public void testReceiptsOrderQuery(String oid) {
/* 203 */     SandPayConfig config = new SandPayConfig();
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 208 */     config.setAccessMid("6888804128472");
/*     */ 
/*     */     
/* 211 */     config.setEncryptType("AES");
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 216 */     config.setPrivateKeyPath("cert/prod/yunshang.pfx");
/* 217 */     config.setPrivateKeyPassword("123123");
/* 218 */     config.setSandPublicKeyPath("cert/prod/sand_pro.cer");
/*     */ 
/*     */ 
/*     */     
/* 222 */     config.setVersion("4.0.0");
/*     */     
/* 224 */     this.sandPayClient = new SandPayClient(config);
/*     */ 
/*     */ 
/*     */     
/* 228 */     JSONObject bizData = new JSONObject();
/*     */     
/* 230 */     bizData.put("mid", "6888804128472");
/*     */     
/* 232 */     bizData.put("outOrderNo", oid);
/*     */ 
/*     */     
/* 235 */     bizData.put("outReqTime", (new SimpleDateFormat("yyyyMMddHHmmss")).format(Long.valueOf(System.currentTimeMillis())));
/*     */ 
/*     */     
/* 238 */     String url = String.format("https://openapi.sandpay.com.cn"
/* 239 */         .concat("/%s"), new Object[] { SandPayMethodEnum.RECEIPTS_ORDER_QUERY.getMethod() });
/*     */ 
/*     */     
/* 242 */     log.debug("请求url:{}", url);
/* 243 */     log.debug("请求报文:{}", bizData);
/*     */     
/* 245 */     JSONObject responseJson = this.sandPayClient.execute(url, bizData);
/* 246 */     log.debug("返回报文:{}", responseJson);
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\SandPayServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */