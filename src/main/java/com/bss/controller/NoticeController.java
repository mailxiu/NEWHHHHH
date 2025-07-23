/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.alipay.api.AlipayConfig;
/*     */ import com.alipay.api.internal.util.AlipaySignature;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.entity.PayAlipayConfig;
/*     */ import com.bss.entity.PaymentConfig;
/*     */ import com.bss.entity.WechatAppPayConfig;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.OrderServiceImpl;
/*     */ import com.bss.service.impl.PayAlipayConfigServiceImpl;
/*     */ import com.bss.service.impl.PaymentConfigServiceImpl;
/*     */ import com.bss.service.impl.WechatAppPayConfigServiceImpl;
/*     */ import com.wechat.pay.java.core.RSAPublicKeyConfig;
/*     */ import com.wechat.pay.java.core.exception.ValidationException;
/*     */ import com.wechat.pay.java.core.notification.NotificationConfig;
/*     */ import com.wechat.pay.java.core.notification.NotificationParser;
/*     */ import com.wechat.pay.java.core.notification.RequestParam;
/*     */ import com.wechat.pay.java.service.payments.model.Transaction;
/*     */ import com.wechat.pay.java.service.refund.model.RefundNotification;
/*     */ import com.wechat.pay.java.service.refund.model.Status;
/*     */ import java.io.ByteArrayOutputStream;
/*     */ import java.util.HashMap;
/*     */ import java.util.Iterator;
/*     */ import java.util.Map;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.ServletInputStream;
/*     */ import javax.servlet.http.HttpServletRequest;
/*     */ import javax.servlet.http.HttpServletResponse;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.ResponseBody;
/*     */ import org.springframework.web.bind.annotation.RestController;
/*     */ 
/*     */ 
/*     */ @RestController
/*     */ @RequestMapping({"notice"})
/*     */ public class NoticeController
/*     */ {
/*  45 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.NoticeController.class);
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private PaymentConfigServiceImpl paymentService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private PayAlipayConfigServiceImpl payAlipayConfigService;
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private WechatAppPayConfigServiceImpl wechatAppPayConfigService;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @ResponseBody
/*     */   @RequestMapping({"/weChatAppPayment"})
/*     */   public String weChatAppPayment(HttpServletRequest request, HttpServletResponse response) throws Exception {
/*  78 */     System.out.println("微信APP支付异步通知...");
/*     */     
/*  80 */     WechatAppPayConfig payment = (WechatAppPayConfig)this.wechatAppPayConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  82 */     ServletInputStream servletInputStream = request.getInputStream();
/*  83 */     ByteArrayOutputStream outSteam = new ByteArrayOutputStream();
/*  84 */     byte[] buffer = new byte[1024];
/*  85 */     int len = 0;
/*     */     
/*  87 */     while ((len = servletInputStream.read(buffer)) != -1) {
/*  88 */       outSteam.write(buffer, 0, len);
/*     */     }
/*     */     
/*  91 */     outSteam.close();
/*  92 */     servletInputStream.close();
/*     */     
/*  94 */     JSONObject data = new JSONObject();
/*     */     
/*  96 */     String wechatPaySerial = request.getHeader("Wechatpay-Serial");
/*  97 */     String wechatPayNonce = request.getHeader("Wechatpay-Nonce");
/*  98 */     String wechatSignature = request.getHeader("Wechatpay-Signature");
/*  99 */     String wechatTimestamp = request.getHeader("Wechatpay-Timestamp");
/*     */ 
/*     */     
/* 102 */     String requestBody = new String(outSteam.toByteArray(), "utf-8");
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 112 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 121 */     RequestParam requestParam = (new RequestParam.Builder()).serialNumber(wechatPaySerial).nonce(wechatPayNonce).signature(wechatSignature).timestamp(wechatTimestamp).body(requestBody).build();
/*     */ 
/*     */     
/* 124 */     NotificationParser parser = new NotificationParser(new NotificationConfig[] { (NotificationConfig)rSAPublicKeyConfig });
/*     */ 
/*     */     
/*     */     try {
/* 128 */       Transaction transaction = (Transaction)parser.parse(requestParam, Transaction.class);
/*     */ 
/*     */       
/* 131 */       String outTradeNo = transaction.getOutTradeNo();
/*     */       
/* 133 */       Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", outTradeNo));
/*     */       
/* 135 */       if (transaction.getTradeState().equals(Transaction.TradeStateEnum.SUCCESS))
/*     */       {
/* 137 */         String transactionId = transaction.getTransactionId();
/*     */         
/* 139 */         order.setTransactionId(transactionId);
/*     */         
/* 141 */         order.setState("已支付");
/*     */         
/* 143 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 146 */         log.info("收到支付通知执行会员升级...");
/*     */ 
/*     */         
/* 149 */         R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*     */         
/* 151 */         System.out.println(r);
/*     */       
/*     */       }
/* 154 */       else if (transaction.getTradeState().equals(Transaction.TradeStateEnum.CLOSED) || transaction.getTradeState().equals(Transaction.TradeStateEnum.NOTPAY))
/*     */       {
/* 156 */         order.setState("已取消");
/* 157 */         this.orderService.saveOrUpdate(order);
/*     */       }
/*     */     
/* 160 */     } catch (ValidationException e) {
/*     */ 
/*     */ 
/*     */       
/* 164 */       response.setStatus(401);
/*     */       
/* 166 */       data.put("code", "FAIL");
/* 167 */       data.put("message", "验签失败");
/*     */       
/* 169 */       return data.toString();
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 179 */     data.put("code", "SUCCESS");
/* 180 */     data.put("message", "成功");
/*     */     
/* 182 */     return data.toString();
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
/*     */   @ResponseBody
/*     */   @RequestMapping({"/weChat_payment"})
/*     */   public String weChat_payment(HttpServletRequest request, HttpServletResponse response) throws Exception {
/* 196 */     System.out.println("收到微信支付异步通知...");
/*     */     
/* 198 */     PaymentConfig payment = (PaymentConfig)this.paymentService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 200 */     ServletInputStream servletInputStream = request.getInputStream();
/* 201 */     ByteArrayOutputStream outSteam = new ByteArrayOutputStream();
/* 202 */     byte[] buffer = new byte[1024];
/* 203 */     int len = 0;
/*     */     
/* 205 */     while ((len = servletInputStream.read(buffer)) != -1) {
/* 206 */       outSteam.write(buffer, 0, len);
/*     */     }
/*     */     
/* 209 */     outSteam.close();
/* 210 */     servletInputStream.close();
/*     */     
/* 212 */     JSONObject data = new JSONObject();
/*     */     
/* 214 */     String wechatPaySerial = request.getHeader("Wechatpay-Serial");
/* 215 */     String wechatPayNonce = request.getHeader("Wechatpay-Nonce");
/* 216 */     String wechatSignature = request.getHeader("Wechatpay-Signature");
/* 217 */     String wechatTimestamp = request.getHeader("Wechatpay-Timestamp");
/*     */     
/* 219 */     System.out.println("异步通知：" + payment);
/*     */ 
/*     */     
/* 222 */     String requestBody = new String(outSteam.toByteArray(), "utf-8");
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 232 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 241 */     RequestParam requestParam = (new RequestParam.Builder()).serialNumber(wechatPaySerial).nonce(wechatPayNonce).signature(wechatSignature).timestamp(wechatTimestamp).body(requestBody).build();
/*     */ 
/*     */     
/* 244 */     NotificationParser parser = new NotificationParser(new NotificationConfig[] { (NotificationConfig)rSAPublicKeyConfig });
/*     */ 
/*     */     
/*     */     try {
/* 248 */       Transaction transaction = (Transaction)parser.parse(requestParam, Transaction.class);
/*     */ 
/*     */       
/* 251 */       String outTradeNo = transaction.getOutTradeNo();
/*     */       
/* 253 */       Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", outTradeNo));
/*     */       
/* 255 */       if (transaction.getTradeState().equals(Transaction.TradeStateEnum.SUCCESS))
/*     */       {
/* 257 */         String transactionId = transaction.getTransactionId();
/*     */         
/* 259 */         order.setTransactionId(transactionId);
/*     */         
/* 261 */         order.setState("已支付");
/*     */         
/* 263 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 266 */         log.info("收到支付通知执行会员升级...");
/*     */ 
/*     */         
/* 269 */         R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*     */         
/* 271 */         System.out.println(r);
/*     */       
/*     */       }
/* 274 */       else if (transaction.getTradeState().equals(Transaction.TradeStateEnum.CLOSED) || transaction.getTradeState().equals(Transaction.TradeStateEnum.NOTPAY))
/*     */       {
/* 276 */         order.setState("已取消");
/* 277 */         this.orderService.saveOrUpdate(order);
/*     */       }
/*     */     
/* 280 */     } catch (ValidationException e) {
/*     */ 
/*     */ 
/*     */       
/* 284 */       response.setStatus(401);
/*     */       
/* 286 */       data.put("code", "FAIL");
/* 287 */       data.put("message", "验签失败");
/*     */       
/* 289 */       return data.toString();
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 299 */     data.put("code", "SUCCESS");
/* 300 */     data.put("message", "成功");
/*     */     
/* 302 */     return data.toString();
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
/*     */   @ResponseBody
/*     */   @RequestMapping({"/weChat_refund"})
/*     */   public String weChat_refund(HttpServletRequest request, HttpServletResponse response) throws Exception {
/* 317 */     System.out.println("收到微信退款异步通知...");
/*     */     
/* 319 */     PaymentConfig payment = (PaymentConfig)this.paymentService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 321 */     ServletInputStream servletInputStream = request.getInputStream();
/* 322 */     ByteArrayOutputStream outSteam = new ByteArrayOutputStream();
/* 323 */     byte[] buffer = new byte[1024];
/* 324 */     int len = 0;
/*     */     
/* 326 */     while ((len = servletInputStream.read(buffer)) != -1) {
/* 327 */       outSteam.write(buffer, 0, len);
/*     */     }
/*     */     
/* 330 */     outSteam.close();
/* 331 */     servletInputStream.close();
/*     */     
/* 333 */     JSONObject data = new JSONObject();
/*     */     
/* 335 */     String wechatPaySerial = request.getHeader("Wechatpay-Serial");
/* 336 */     String wechatPayNonce = request.getHeader("Wechatpay-Nonce");
/* 337 */     String wechatSignature = request.getHeader("Wechatpay-Signature");
/* 338 */     String wechatTimestamp = request.getHeader("Wechatpay-Timestamp");
/*     */ 
/*     */     
/* 341 */     String requestBody = new String(outSteam.toByteArray(), "utf-8");
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 351 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 361 */     RequestParam requestParam = (new RequestParam.Builder()).serialNumber(wechatPaySerial).nonce(wechatPayNonce).signature(wechatSignature).timestamp(wechatTimestamp).body(requestBody).build();
/*     */ 
/*     */     
/* 364 */     NotificationParser parser = new NotificationParser(new NotificationConfig[] { (NotificationConfig)rSAPublicKeyConfig });
/*     */ 
/*     */     
/*     */     try {
/* 368 */       RefundNotification refundNotification = (RefundNotification)parser.parse(requestParam, RefundNotification.class);
/*     */ 
/*     */       
/* 371 */       String outTradeNo = refundNotification.getOutTradeNo();
/*     */       
/* 373 */       String outRefundNo = refundNotification.getOutRefundNo();
/*     */ 
/*     */       
/* 376 */       String userReceivedAccount = refundNotification.getUserReceivedAccount();
/*     */       
/* 378 */       String transactionId = refundNotification.getTransactionId();
/*     */ 
/*     */       
/* 381 */       Status refundStatus = refundNotification.getRefundStatus();
/*     */       
/* 383 */       Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", outTradeNo));
/*     */       
/* 385 */       if (refundStatus.equals(Status.SUCCESS)) {
/*     */         
/* 387 */         order.setState("已退款");
/*     */         
/* 389 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 392 */         R r = this.memberService.upgrade(order.getUid(), Integer.valueOf(1));
/*     */         
/* 394 */         System.out.println(r);
/*     */       } 
/*     */       
/* 397 */       log.info("执行订单状态修改...");
/*     */     }
/* 399 */     catch (ValidationException e) {
/*     */ 
/*     */ 
/*     */       
/* 403 */       response.setStatus(401);
/*     */       
/* 405 */       data.put("code", "FAIL");
/* 406 */       data.put("message", "验签失败");
/*     */       
/* 408 */       return data.toString();
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 417 */     data.put("code", "SUCCESS");
/* 418 */     data.put("message", "成功");
/*     */     
/* 420 */     return data.toString();
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
/*     */   @RequestMapping({"/alipayNotifyNotice"})
/*     */   @ResponseBody
/*     */   public String alipayNotifyNotice(HttpServletRequest request, HttpServletRequest response) throws Exception {
/* 435 */     System.out.println("支付宝支付成功, 进入异步通知接口...");
/*     */     
/* 437 */     AlipayConfig alipayConfig = getAlipayConfig();
/*     */ 
/*     */     
/* 440 */     Map<String, String> params = new HashMap<>();
/* 441 */     Map<String, String[]> requestParams = request.getParameterMap();
/* 442 */     for (Iterator<String> iter = requestParams.keySet().iterator(); iter.hasNext(); ) {
/* 443 */       String name = iter.next();
/* 444 */       String[] values = requestParams.get(name);
/* 445 */       String valueStr = "";
/* 446 */       for (int i = 0; i < values.length; i++) {
/* 447 */         valueStr = (i == values.length - 1) ? (valueStr + values[i]) : (valueStr + values[i] + ",");
/*     */       }
/*     */ 
/*     */ 
/*     */       
/* 452 */       params.put(name, valueStr);
/*     */     } 
/*     */     
/* 455 */     boolean signVerified = AlipaySignature.rsaCheckV1(params, alipayConfig.getAlipayPublicKey(), alipayConfig.getCharset(), alipayConfig.getSignType());
/*     */ 
/*     */     
/* 458 */     if (signVerified) {
/*     */       
/* 460 */       String out_trade_no = new String(request.getParameter("out_trade_no").getBytes("ISO-8859-1"), "UTF-8");
/*     */ 
/*     */       
/* 463 */       String trade_no = new String(request.getParameter("trade_no").getBytes("ISO-8859-1"), "UTF-8");
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */       
/* 469 */       String trade_status = new String(request.getParameter("trade_status").getBytes("ISO-8859-1"), "UTF-8");
/*     */ 
/*     */       
/* 472 */       if (trade_status.equals("TRADE_SUCCESS"))
/*     */       {
/* 474 */         log.info("支付宝异步回调：{}支付成功！", trade_no);
/*     */ 
/*     */         
/* 477 */         Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", out_trade_no));
/*     */         
/* 479 */         order.setTransactionId(trade_no);
/*     */         
/* 481 */         order.setState("已支付");
/*     */         
/* 483 */         this.orderService.saveOrUpdate(order);
/*     */ 
/*     */         
/* 486 */         log.info("收到支付通知执行会员升级...");
/*     */ 
/*     */         
/* 489 */         R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*     */         
/* 491 */         System.out.println(r);
/*     */       }
/*     */     
/*     */     } else {
/*     */       
/* 496 */       System.out.println("支付, 验签失败...");
/*     */     } 
/*     */     
/* 499 */     return "success";
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
/*     */   @RequestMapping({"/alipayRefundNotice"})
/*     */   @ResponseBody
/*     */   public String alipayRefundNotice(HttpServletRequest request, HttpServletRequest response) throws Exception {
/* 514 */     System.out.println("支付宝退款成功, 进入异步通知接口...");
/*     */     
/* 516 */     AlipayConfig alipayConfig = getAlipayConfig();
/*     */ 
/*     */     
/* 519 */     Map<String, String> params = new HashMap<>();
/* 520 */     Map<String, String[]> requestParams = request.getParameterMap();
/* 521 */     for (Iterator<String> iter = requestParams.keySet().iterator(); iter.hasNext(); ) {
/* 522 */       String name = iter.next();
/* 523 */       String[] values = requestParams.get(name);
/* 524 */       String valueStr = "";
/* 525 */       for (int i = 0; i < values.length; i++) {
/* 526 */         valueStr = (i == values.length - 1) ? (valueStr + values[i]) : (valueStr + values[i] + ",");
/*     */       }
/*     */ 
/*     */ 
/*     */       
/* 531 */       params.put(name, valueStr);
/*     */     } 
/*     */     
/* 534 */     boolean signVerified = AlipaySignature.rsaCheckV1(params, alipayConfig.getAlipayPublicKey(), alipayConfig.getCharset(), alipayConfig.getSignType());
/*     */     
/* 536 */     if (signVerified) {
/*     */       
/* 538 */       String out_trade_no = new String(request.getParameter("out_trade_no").getBytes("ISO-8859-1"), "UTF-8");
/*     */ 
/*     */       
/* 541 */       String trade_no = new String(request.getParameter("trade_no").getBytes("ISO-8859-1"), "UTF-8");
/*     */ 
/*     */       
/* 544 */       String trade_status = new String(request.getParameter("trade_status").getBytes("ISO-8859-1"), "UTF-8");
/*     */       
/* 546 */       Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", out_trade_no));
/*     */       
/* 548 */       order.setState("已退款");
/*     */       
/* 550 */       this.orderService.saveOrUpdate(order);
/*     */ 
/*     */       
/* 553 */       R r = this.memberService.upgrade(order.getUid(), Integer.valueOf(1));
/*     */       
/* 555 */       System.out.println(r);
/*     */       
/* 557 */       if (trade_status.equals("TRADE_SUCCESS")) {
/* 558 */         System.out.println("tuikunnn");
/*     */       }
/*     */     } else {
/*     */       
/* 562 */       System.out.println("支付, 验签失败...");
/*     */     } 
/*     */     
/* 565 */     return "success";
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   private AlipayConfig getAlipayConfig() {
/* 572 */     PayAlipayConfig payAlipayConfig = (PayAlipayConfig)this.payAlipayConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 574 */     String privateKey = payAlipayConfig.getPrivateKey();
/* 575 */     String alipayPublicKey = payAlipayConfig.getAlipayPublicKey();
/*     */     
/* 577 */     AlipayConfig alipayConfig = new AlipayConfig();
/* 578 */     alipayConfig.setServerUrl("https://openapi.alipay.com/gateway.do");
/* 579 */     alipayConfig.setAppId(payAlipayConfig.getAppid());
/* 580 */     alipayConfig.setPrivateKey(privateKey);
/* 581 */     alipayConfig.setFormat("json");
/* 582 */     alipayConfig.setAlipayPublicKey(alipayPublicKey);
/* 583 */     alipayConfig.setCharset("UTF-8");
/* 584 */     alipayConfig.setSignType("RSA2");
/* 585 */     return alipayConfig;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\NoticeController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */