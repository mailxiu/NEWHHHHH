/*     */ package com.bss.service.impl;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.alipay.api.AlipayApiException;
/*     */ import com.alipay.api.AlipayClient;
/*     */ import com.alipay.api.AlipayConfig;
/*     */ import com.alipay.api.AlipayObject;
/*     */ import com.alipay.api.AlipayRequest;
/*     */ import com.alipay.api.DefaultAlipayClient;
/*     */ import com.alipay.api.domain.AlipayFundTransUniTransferModel;
/*     */ import com.alipay.api.domain.AlipayTradeAppPayModel;
/*     */ import com.alipay.api.domain.AlipayTradeRefundModel;
/*     */ import com.alipay.api.domain.AlipayTradeWapPayModel;
/*     */ import com.alipay.api.domain.Participant;
/*     */ import com.alipay.api.request.AlipayFundTransUniTransferRequest;
/*     */ import com.alipay.api.request.AlipayTradeAppPayRequest;
/*     */ import com.alipay.api.request.AlipayTradeRefundRequest;
/*     */ import com.alipay.api.request.AlipayTradeWapPayRequest;
/*     */ import com.alipay.api.response.AlipayFundTransUniTransferResponse;
/*     */ import com.alipay.api.response.AlipayTradeAppPayResponse;
/*     */ import com.alipay.api.response.AlipayTradeRefundResponse;
/*     */ import com.alipay.api.response.AlipayTradeWapPayResponse;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.entity.PayAlipayConfig;
/*     */ import com.bss.entity.SystemConfig;
/*     */ import com.bss.entity.Withdrawal;
/*     */
 import com.bss.utils.R;

/*     */
/*     */
/*     */
/*     */
/*     */ import javax.annotation.Resource;
/*     */ import org.springframework.stereotype.Service;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
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
/*     */ 
/*     */ 
/*     */ 
/*     */ @Service
/*     */ public class AlipayServiceImpl
/*     */ {
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */   @Resource
/*     */   private WithdrawalServiceImpl withdrawalService;
/*     */   @Resource
/*     */   private SystemConfigServiceImpl systemConfigService;
/*     */   @Resource
/*     */   private PayAlipayConfigServiceImpl payAlipayConfigService;
/*     */   
/*     */   @RequestMapping({"/payment_order"})
/*     */   public R payment_order(String oid) {
/*     */     DefaultAlipayClient defaultAlipayClient;
/*  74 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  76 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/*  78 */     if (order == null) {
/*  79 */       return R.fail("订单不存在");
/*     */     }
/*     */ 
/*     */     
/*  83 */     AlipayClient alipayClient = null;
/*     */     try {
/*  85 */       defaultAlipayClient = new DefaultAlipayClient(getAlipayConfig());
/*  86 */     } catch (AlipayApiException e) {
/*  87 */       e.printStackTrace();
/*     */       
/*  89 */       return R.fail("加载支付宝请求失败！");
/*     */     } 
/*     */ 
/*     */     
/*  93 */     AlipayTradeAppPayRequest request = new AlipayTradeAppPayRequest();
/*  94 */     AlipayTradeAppPayModel model = new AlipayTradeAppPayModel();
/*     */ 
/*     */     
/*  97 */     model.setOutTradeNo(order.getOid());
/*     */ 
/*     */     
/* 100 */     model.setTotalAmount(order.getMoney().toPlainString());
/*     */ 
/*     */     
/* 103 */     model.setSubject("开通会员");
/*     */ 
/*     */     
/* 106 */     model.setProductCode("QUICK_MSECURITY_PAY");
/*     */     
/* 108 */     model.setPassbackParams("member");
/*     */     
/* 110 */     request.setBizModel((AlipayObject)model);
/*     */     
/* 112 */     request.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/alipayNotifyNotice");
/*     */     
/* 114 */     AlipayTradeAppPayResponse response = null;
/*     */     try {
/* 116 */       response = (AlipayTradeAppPayResponse)defaultAlipayClient.sdkExecute((AlipayRequest)request);
/* 117 */     } catch (AlipayApiException e) {
/* 118 */       e.printStackTrace();
/* 119 */       R.fail("请求支付宝下单失败");
/*     */     } 
/* 121 */     String orderStr = response.getBody();
/*     */     
/* 123 */     System.out.println(orderStr);
/*     */     
/* 125 */     if (response.isSuccess()) {
/* 126 */       return R.success(orderStr);
/*     */     }
/* 128 */     System.out.println("调用失败");
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 133 */     return R.fail("支付请求失败！");
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
/*     */   @RequestMapping({"/payment_order_h5"})
/*     */   public R payment_order_h5(String oid) {
/*     */     DefaultAlipayClient defaultAlipayClient;
/* 147 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 149 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/* 151 */     if (order == null) {
/* 152 */       return R.fail("订单不存在");
/*     */     }
/*     */ 
/*     */     
/* 156 */     AlipayClient alipayClient = null;
/*     */     try {
/* 158 */       defaultAlipayClient = new DefaultAlipayClient(getAlipayConfig());
/* 159 */     } catch (AlipayApiException e) {
/* 160 */       e.printStackTrace();
/*     */       
/* 162 */       return R.fail("加载支付宝请求失败！");
/*     */     } 
/*     */ 
/*     */     
/* 166 */     AlipayTradeWapPayRequest request = new AlipayTradeWapPayRequest();
/* 167 */     AlipayTradeWapPayModel model = new AlipayTradeWapPayModel();
/*     */ 
/*     */     
/* 170 */     model.setOutTradeNo(order.getOid());
/*     */ 
/*     */     
/* 173 */     model.setTotalAmount(order.getMoney().toPlainString());
/*     */ 
/*     */     
/* 176 */     model.setSubject("开通会员");
/*     */ 
/*     */     
/* 179 */     model.setProductCode("QUICK_WAP_WAY");
/*     */     
/* 181 */     request.setBizModel((AlipayObject)model);
/*     */     
/* 183 */     request.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/alipayNotifyNotice");
/*     */     
/* 185 */     AlipayTradeWapPayResponse response = null;
/*     */     try {
/* 187 */       response = (AlipayTradeWapPayResponse)defaultAlipayClient.pageExecute((AlipayRequest)request, "POST");
/* 188 */     } catch (AlipayApiException e) {
/* 189 */       e.printStackTrace();
/* 190 */       return R.fail("支付请求失败！");
/*     */     } 
/*     */ 
/*     */     
/* 194 */     String pageRedirectionData = response.getBody();
/* 195 */     System.out.println(pageRedirectionData);
/*     */     
/* 197 */     if (response.isSuccess()) {
/* 198 */       System.out.println("调用成功");
/* 199 */       return R.success(pageRedirectionData);
/*     */     } 
/* 201 */     System.out.println("调用失败");
/* 202 */     return R.fail("支付请求失败！");
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
/*     */   @RequestMapping({"/refund"})
/*     */   public R refund(String oid) {
/*     */     DefaultAlipayClient defaultAlipayClient;
/* 218 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 220 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/* 222 */     if (order == null || order.getTransactionId() == null) {
/* 223 */       return R.fail("订单不存在或未支付");
/*     */     }
/*     */ 
/*     */     
/* 227 */     AlipayClient alipayClient = null;
/*     */     try {
/* 229 */       defaultAlipayClient = new DefaultAlipayClient(getAlipayConfig());
/* 230 */     } catch (AlipayApiException e) {
/* 231 */       e.printStackTrace();
/* 232 */       return R.fail("加载支付宝请求失败！");
/*     */     } 
/*     */ 
/*     */     
/* 236 */     AlipayTradeRefundRequest request = new AlipayTradeRefundRequest();
/* 237 */     AlipayTradeRefundModel model = new AlipayTradeRefundModel();
/*     */ 
/*     */     
/* 240 */     model.setOutTradeNo(order.getOid());
/*     */ 
/*     */     
/* 243 */     model.setTradeNo(order.getTransactionId());
/*     */ 
/*     */     
/* 246 */     model.setRefundAmount(order.getMoney().toString());
/*     */ 
/*     */     
/* 249 */     model.setRefundReason("支付退款");
/*     */     
/* 251 */     request.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/alipayRefundNotice");
/*     */     
/* 253 */     request.setBizModel((AlipayObject)model);
/*     */ 
/*     */ 
/*     */     
/* 257 */     AlipayTradeRefundResponse response = null;
/*     */     try {
/* 259 */       response = (AlipayTradeRefundResponse)defaultAlipayClient.execute((AlipayRequest)request);
/* 260 */     } catch (AlipayApiException e) {
/* 261 */       e.printStackTrace();
/* 262 */       return R.fail("支付请求失败！");
/*     */     } 
/*     */     
/* 265 */     if (response.isSuccess()) {
/*     */       
/* 267 */       if (response.getFundChange().equals("Y")) {
/*     */         
/* 269 */         order.setState("已退款");
/*     */         
/* 271 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 274 */         com.baomidou.mybatisplus.extension.api.R r = this.memberService.upgrade(order.getUid(), Integer.valueOf(1));
/*     */         
/* 276 */         System.out.println(r);
/*     */       } else {
/*     */         
/* 279 */         return R.fail("退款调用失败");
/*     */       } 
/*     */       
/* 282 */       System.out.println("调用成功");
/* 283 */       return R.success("调用成功");
/*     */     } 
/* 285 */     System.out.println("调用失败");
/* 286 */     return R.fail("调用失败");
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
/*     */ 
/*     */   
/*     */   public R transfer(String oid) throws AlipayApiException {
/* 304 */     Withdrawal withdrawal = (Withdrawal)this.withdrawalService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/* 306 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", withdrawal.getUid()));
/*     */ 
/*     */     
/* 309 */     DefaultAlipayClient defaultAlipayClient = new DefaultAlipayClient(getAlipayConfigComplete());
/*     */ 
/*     */     
/* 312 */     AlipayFundTransUniTransferRequest request = new AlipayFundTransUniTransferRequest();
/* 313 */     AlipayFundTransUniTransferModel model = new AlipayFundTransUniTransferModel();
/*     */ 
/*     */     
/* 316 */     model.setOutBizNo(withdrawal.getOid());
/*     */ 
/*     */     
/* 319 */     model.setTransAmount(withdrawal.getRealMoney().toString());
/*     */ 
/*     */     
/* 322 */     model.setBizScene("DIRECT_TRANSFER");
/*     */ 
/*     */     
/* 325 */     model.setProductCode("TRANS_ACCOUNT_NO_PWD");
/*     */ 
/*     */     
/* 328 */     model.setOrderTitle("云上回收提现");
/*     */ 
/*     */     
/* 331 */     Participant payeeInfo = new Participant();
/*     */     
/* 333 */     payeeInfo.setIdentity(member.getAlipayAccount());
/* 334 */     payeeInfo.setName(member.getAlipayName());
/* 335 */     payeeInfo.setIdentityType("ALIPAY_LOGON_ID");
/* 336 */     model.setPayeeInfo(payeeInfo);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 344 */     request.setBizModel((AlipayObject)model);
/* 345 */     AlipayFundTransUniTransferResponse response = (AlipayFundTransUniTransferResponse)defaultAlipayClient.certificateExecute((AlipayRequest)request);
/*     */     
/* 347 */     if (response.isSuccess()) {
/* 348 */       System.out.println("调用成功");
/*     */       
/* 350 */       withdrawal.setState("已处理");
/*     */       
/* 352 */       this.withdrawalService.saveOrUpdate(withdrawal);
/*     */       
/* 354 */       return R.success();
/*     */     } 
/* 356 */     System.out.println("调用失败");
/*     */     
/* 358 */     JSONObject data = JSON.parseObject(response.getBody());
/*     */     
/* 360 */     JSONObject alipayFundTransUniTransferResponse = data.getJSONObject("alipay_fund_trans_uni_transfer_response");
/*     */     
/* 362 */     String sub_msg = alipayFundTransUniTransferResponse.getString("sub_msg");
/*     */     
/* 364 */     withdrawal.setState("已驳回");
/*     */     
/* 366 */     withdrawal.setInfo(sub_msg);
/*     */     
/* 368 */     member.setPoints(Double.valueOf(member.getPoints().doubleValue() + withdrawal.getPoints().doubleValue()));
/*     */     
/* 370 */     this.memberService.saveOrUpdate(member);
/*     */     
/* 372 */     boolean update = this.withdrawalService.saveOrUpdate(withdrawal);
/*     */     
/* 374 */     return R.fail(sub_msg);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   private AlipayConfig getAlipayConfig() {
/* 385 */     PayAlipayConfig payAlipayConfig = (PayAlipayConfig)this.payAlipayConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 387 */     String privateKey = payAlipayConfig.getPrivateKey();
/* 388 */     String alipayPublicKey = payAlipayConfig.getAlipayPublicKey();
/*     */     
/* 390 */     AlipayConfig alipayConfig = new AlipayConfig();
/* 391 */     alipayConfig.setServerUrl("https://openapi.alipay.com/gateway.do");
/* 392 */     alipayConfig.setAppId(payAlipayConfig.getAppid());
/* 393 */     alipayConfig.setPrivateKey(privateKey);
/* 394 */     alipayConfig.setFormat("json");
/* 395 */     alipayConfig.setAlipayPublicKey(alipayPublicKey);
/* 396 */     alipayConfig.setCharset("UTF-8");
/* 397 */     alipayConfig.setSignType("RSA2");
/* 398 */     return alipayConfig;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   private static AlipayConfig getAlipayConfigComplete() {
/* 406 */     String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCBh5lgAobA7uteByf0DMFUmqDGnf8OxAEcW+3YYf8veC5QtRXp6ynkFRjHRNOzGa0vuTeGJNK9HVC0/B50r8njgFyveFHAN052JsFfhoI8MoKW0z14zU//YXcp86M8EbQuhtfskhDilRFezR6H50zZlt76Hf55q9PBdLizuluh93QauuqwIqIxHjNXJ6c5iHMgn/FqeTV5M61riQ12d/+ao5UPE5MoDqphCSRTOck8RkMRHAhTrLCZ51iAPjp2KaE0YAby9aG/F/z/4eDvpvXxN77YjEq+rBy5v+12hRvWfS0tqimbVpDlDjCBHU1RyFYbiGpVuAsxQLWD9X9dPorjAgMBAAECggEAV41aZIUQpJRZz2Ky5MlCXHdwORBOeKKPxaV1rQ8AOAvZ8n+UYlqsJBkGeJrTJXozj9B38Vouf9my1cKcq26u3fHDtG91gqFfjYlAp9r5aMsTbfM219KfQhWVQGwIZ+/nhJNsm+FXPHBaH2QyQNZdIa5S5WkkuwUjyt2kgwdyLJVjEeZHlamWy+I8wiQoKDRcG3/dCwcFnlV2NHfV0YwYYYYR8jONGGfFgyZyAv14EjdHQZFVVNyNE6vUZyZE3y+ISr6tYxnwwiTrF/jToLxw8a60O/rs7mHkSVwxWUe93CZSqaBv2GQd914e+ZXF59SxnVV375u6N8e+KkQj9c31sQKBgQDoLcmCYxcXqRWrXRIoatG9r8wHkH53UU5KO0ArsMBXmxBjztZ/QlHdFMakNWPVx5DY1V43WkgOagACD8mLbaw6OFaakus4iruQ42jz5STRgRZd97V8x47PK5/1rfREyIVoKx38FlERstbyVZqJbbqGA81oK49/OFCPLogow5dJNQKBgQCO0bdF817lOBprW1zyGObtYfbZthRl4/aDb6Ji1V4X0zNs18SZrrdM/3Hqo5yssARWLNnrnUyJCRMnZ14EqJoF6wpzhPMTdGIUID2iofQbXTwlvkAmtlaUuP20pUXMYxeSnfOCmAjkkzjnvYUOgCR1VqV91Hf8ihimSw7HwREetwKBgDxlbL3WOPOWsGRbWZXZ86V8TX7KP5uaMttsfkzfNamUVLch3vpLri/sb5/Xo5jAyRUeq9uKSKQ3PrlKkgsLBHpAnYaoITgcHp6aCXsoaGN3SPI4taU35BZQKtQl5BzgbJOkY7Bnvb703qU7T2/gc1zZMF2gtztI0uvsFs9D0d7hAoGAR/2IX5dEr1BvaMw99r78sI3gC3APqiiV2z0LYrxg2KuaUXQV4s3CEer1diwQzq9PEE09b9nzeWP8prEhIEIImZEXzJEoohbZVYHG79KpJJ4DspbK6Xih/gedw1BH9bXBbSN3Ws3eNbHMTmwmxN9tAUSy2NGfxcmqkTBme+RjB9MCgYEAg/iENPpIT/dj53jVW6qjzMszlIxSaD3JijedqYUkPwGr6J0cT+Sv27C6POzaKIokVe7bEgi0hWHAdAlKcRoPEoOjUrirkaW/Sl3fNT6krc0vqHZjttSum9TNh2G0Wc4Lj55OgymWhR1eigUncEPZam1c45UP/WKwmJygf3hQx74=";
/* 407 */     AlipayConfig alipayConfig = new AlipayConfig();
/* 408 */     alipayConfig.setPrivateKey(privateKey);
/* 409 */     alipayConfig.setServerUrl("https://openapi.alipay.com/gateway.do");
/* 410 */     alipayConfig.setAppId("2021005136686959");
/* 411 */     alipayConfig.setCharset("UTF-8");
/* 412 */     alipayConfig.setSignType("RSA2");
/* 413 */     alipayConfig.setFormat("json");
/* 414 */     alipayConfig.setAppCertPath("/www/cert/appCertPublicKey_2021005136686959.crt");
/* 415 */     alipayConfig.setAlipayPublicCertPath("/www/cert/alipayCertPublicKey_RSA2.crt");
/* 416 */     alipayConfig.setRootCertPath("/www/cert/alipayRootCert.crt");
/* 417 */     return alipayConfig;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\AlipayServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */