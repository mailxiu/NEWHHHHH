/*     */ package com.bss.service.impl;
/*     */

/*     */
/*     */
import cn.hutool.captcha.generator.RandomGenerator;
import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bss.entity.AppletConfig;
import com.bss.entity.OfficialConfig;
import com.bss.entity.Order;
import com.bss.entity.PaymentConfig;
import com.bss.entity.SystemConfig;
import com.bss.entity.WechatAppPayConfig;
import com.bss.service.impl.AppletConfigServiceImpl;
import com.bss.service.impl.MemberServiceImpl;
import com.bss.service.impl.OfficialConfigServiceImpl;
import com.bss.service.impl.OrderServiceImpl;
import com.bss.service.impl.PaymentConfigServiceImpl;
import com.bss.service.impl.SystemConfigServiceImpl;
import com.bss.service.impl.WechatAppPayConfigServiceImpl;
import com.bss.utils.R;
import com.wechat.pay.java.core.Config;
import com.wechat.pay.java.core.RSAPublicKeyConfig;
import com.wechat.pay.java.core.exception.ServiceException;
import com.wechat.pay.java.service.payments.app.AppServiceExtension;
//import com.wechat.pay.java.service.payments.app.model.Amount;
import com.wechat.pay.java.service.payments.jsapi.JsapiServiceExtension;
import com.wechat.pay.java.service.payments.jsapi.model.Payer;
import com.wechat.pay.java.service.refund.RefundService;
import com.wechat.pay.java.service.refund.model.AmountReq;
import com.wechat.pay.java.service.refund.model.CreateRequest;
import com.wechat.pay.java.service.refund.model.Refund;
import com.wechat.pay.java.service.refund.model.Status;
import java.math.BigDecimal;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import javax.annotation.Resource;
import com.wechat.pay.java.service.payments.jsapi.model.PrepayWithRequestPaymentResponse;
import org.springframework.stereotype.Service;
import com.wechat.pay.java.service.payments.jsapi.model.Amount;
import com.wechat.pay.java.service.payments.jsapi.model.PrepayRequest;
/*     */ @Service
/*     */ public class WxtPayServiceImpl
/*     */ {
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */   @Resource
/*     */   private AppletConfigServiceImpl appletConfigService;
/*     */   @Resource
/*     */   private OfficialConfigServiceImpl officialConfigService;
/*     */   @Resource
/*     */   private PaymentConfigServiceImpl paymentService;
/*     */   @Resource
/*     */   private SystemConfigServiceImpl systemConfigService;
/*     */   @Resource
/*     */   private WechatAppPayConfigServiceImpl wechatAppPayConfigService;
/*     */
/*     */   public R goWXAlipayJS(String oid, String openid) {
/*  71 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/*  73 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */
/*  75 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/*  77 */     PaymentConfig payment = (PaymentConfig)this.paymentService.getOne((Wrapper)new QueryWrapper());
/*     */
/*  79 */     System.out.println("异步通知：" + payment);
/*     */
/*  81 */     if (payment == null) {
/*  82 */       return R.fail("商家未配置支付参数");
/*     */     }
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
/*  95 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */
/*  97 */     JsapiServiceExtension service = (new JsapiServiceExtension.Builder()).config((Config)rSAPublicKeyConfig).build();
/*     */
/*  99 */     Payer payer = new Payer();
/*     */
/* 101 */     payer.setOpenid(openid);
/*     */
/* 103 */     PrepayRequest prepayRequest = new PrepayRequest();
/*     */
/* 105 */     BigDecimal c = new BigDecimal(100);
/*     */
/* 107 */     BigDecimal money = order.getMoney().multiply(c);
/*     */
/* 109 */     Amount amount = new Amount();
/* 110 */     amount.setTotal(Integer.valueOf(money.intValue()));
/* 111 */     prepayRequest.setAmount(amount);
/* 112 */     prepayRequest.setAppid(applet.getAppId());
/* 113 */     prepayRequest.setMchid(payment.getMerchantId());
/* 114 */     prepayRequest.setDescription("技术服务费");
/* 115 */     prepayRequest.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/weChat_payment");
/* 116 */     prepayRequest.setOutTradeNo(order.getOid());
/* 117 */     prepayRequest.setPayer(payer);
/*     */
/*     */
/* 120 */     PrepayWithRequestPaymentResponse response = null;
/*     */
/*     */     try {
/* 123 */       response = service.prepayWithRequestPayment(prepayRequest);
/*     */
/* 125 */       return R.success(JSON.toJSON(response));
/*     */     }
/* 127 */     catch (ServiceException e) {
/*     */
/* 129 */       System.out.println("捕获微信支付异常");
/* 130 */       System.out.println(e.getResponseBody());
/*     */
/* 132 */       return R.fail(e.getResponseBody());
/*     */     }
/*     */   }
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */   public R goWXAlipayOfficial(String oid, String openid) {
/* 144 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 146 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */
/* 148 */     OfficialConfig official = (OfficialConfig)this.officialConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 150 */     PaymentConfig payment = (PaymentConfig)this.paymentService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 152 */     System.out.println("异步通知：" + payment);
/*     */
/*     */
/* 155 */     if (payment == null) {
/* 156 */       return R.fail("商家未配置支付参数");
/*     */     }
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
/* 169 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */
/* 171 */     JsapiServiceExtension service = (new JsapiServiceExtension.Builder()).config((Config)rSAPublicKeyConfig).build();
/*     */
/* 173 */     Payer payer = new Payer();
/*     */
/* 175 */     payer.setOpenid(openid);
/*     */
/* 177 */     PrepayRequest prepayRequest = new PrepayRequest();
/*     */
/* 179 */     BigDecimal c = new BigDecimal(100);
/*     */
/* 181 */     BigDecimal money = order.getMoney().multiply(c);
/*     */
/* 183 */     Amount amount = new Amount();
/* 184 */     amount.setTotal(Integer.valueOf(money.intValue()));
/* 185 */     prepayRequest.setAmount(amount);
/* 186 */     prepayRequest.setAppid(official.getAppId());
/* 187 */     prepayRequest.setMchid(payment.getMerchantId());
/* 188 */     prepayRequest.setDescription("技术服务费");
/* 189 */     prepayRequest.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/weChat_payment");
/* 190 */     prepayRequest.setOutTradeNo(order.getOid());
/* 191 */     prepayRequest.setPayer(payer);
/*     */
/*     */
/*     */
/* 195 */     com.wechat.pay.java.service.payments.jsapi.model.PrepayWithRequestPaymentResponse response = null;
/*     */
/*     */     try {
/* 198 */       response = service.prepayWithRequestPayment(prepayRequest);
/*     */
/* 200 */       System.out.println(response);
/*     */
/* 202 */       return R.success(JSON.toJSON(response));
/*     */     }
/* 204 */     catch (ServiceException e) {
/*     */
/* 206 */       System.out.println("捕获微信支付异常");
/* 207 */       System.out.println(e.getResponseBody());
/*     */
/* 209 */       return R.fail(e.getResponseBody());
/*     */     }
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
/*     */   public R goWeChatAppPay(String oid) {
/* 222 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/*     */
/* 225 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */
/*     */
/* 228 */     WechatAppPayConfig payment = (WechatAppPayConfig)this.wechatAppPayConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 230 */     if (payment == null) {
/* 231 */       return R.fail("商家未配置支付参数");
/*     */     }
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
/* 244 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */
/* 246 */     AppServiceExtension service = (new AppServiceExtension.Builder()).config((Config)rSAPublicKeyConfig).build();
/*     */

    com.wechat.pay.java.service.payments.app.model.PrepayRequest prepayRequest = new com.wechat.pay.java.service.payments.app.model.PrepayRequest();

//    /* 248 */     PrepayRequest prepayRequest = new PrepayRequest();
/*     */
/* 250 */     BigDecimal c = new BigDecimal(100);
/*     */
/* 252 */     BigDecimal money = order.getMoney().multiply(c);
/*     */
    com.wechat.pay.java.service.payments.app.model.Amount  amount = new com.wechat.pay.java.service.payments.app.model.Amount();
/* 255 */     amount.setTotal(Integer.valueOf(money.intValue()));
/* 256 */     prepayRequest.setAmount(amount);
/* 257 */     prepayRequest.setAppid("wx3afffd1bbcb26fdd");
/* 258 */     prepayRequest.setMchid(payment.getMerchantId());
/* 259 */     prepayRequest.setDescription("技术服务费");
/* 260 */     prepayRequest.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/weChatAppPayment");
/* 261 */     prepayRequest.setOutTradeNo(order.getOid());
/*     */
/*     */
/*     */
    /* 195 */     com.wechat.pay.java.service.payments.app.model.PrepayWithRequestPaymentResponse response = null;

/*     */
/*     */     try {
/* 268 */       response = service.prepayWithRequestPayment(prepayRequest);
/*     */

/* 270 */       return R.success(JSON.toJSON(response));
/*     */     }
/* 272 */     catch (ServiceException e) {
/*     */
/* 274 */       System.out.println("捕获微信支付异常");
/* 275 */       System.out.println(e.getResponseBody());
/*     */
/* 277 */       return R.fail(e.getResponseBody());
/*     */     }
/*     */   }
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */   public R refund(String oid) {
/* 289 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 291 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */
/* 293 */     PaymentConfig payment = (PaymentConfig)this.paymentService.getOne((Wrapper)new QueryWrapper());
/*     */
/* 295 */     Calendar calendar = Calendar.getInstance();
/*     */
/* 297 */     DateFormat orderId = new SimpleDateFormat("yyyyMMddHHmmss");
/*     */
/* 299 */     RandomGenerator randomGenerator = new RandomGenerator("123456789", 4);
/*     */
/* 301 */     String refundNo = orderId.format(calendar.getTime()) + randomGenerator.generate();
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
/* 313 */     RSAPublicKeyConfig rSAPublicKeyConfig = ((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)((RSAPublicKeyConfig.Builder)(new RSAPublicKeyConfig.Builder()).merchantId(payment.getMerchantId())).privateKeyFromPath(payment.getPrivateKeyFromPath())).publicKeyFromPath(payment.getPublicKeyFromPath()).publicKeyId(payment.getPublicKeyId()).merchantSerialNumber(payment.getMerchantSerialNumber())).apiV3Key(payment.getApiV3Key()).build();
/*     */
/* 315 */     RefundService service = (new RefundService.Builder()).config((Config)rSAPublicKeyConfig).build();
/*     */
/* 317 */     BigDecimal c = new BigDecimal(100);
/*     */
/* 319 */     BigDecimal money = order.getMoney().multiply(c);
/*     */
/* 321 */     AmountReq amount = new AmountReq();
/*     */
/* 323 */     amount.setRefund(Long.valueOf(money.longValue()));
/* 324 */     amount.setTotal(Long.valueOf(money.longValue()));
/* 325 */     amount.setCurrency("CNY");
/*     */
/* 327 */     CreateRequest request = new CreateRequest();
/* 328 */     request.setTransactionId(order.getTransactionId());
/* 329 */     request.setOutTradeNo(oid);
/* 330 */     request.setOutRefundNo(refundNo);
/* 331 */     request.setReason("取消会员");
/* 332 */     request.setNotifyUrl(systemConfig.getServiceUrl() + "/notice/weChat_refund");
/* 333 */     request.setAmount(amount);
/*     */
/* 335 */     Refund refund = null;
/*     */
/*     */
/*     */     try {
/* 339 */       refund = service.create(request);
/*     */
/* 341 */       if (refund.getStatus().equals(Status.SUCCESS)) {
/*     */
/* 343 */         order.setState("已退款");
/*     */
/* 345 */         this.orderService.saveOrUpdate(order);
/*     */
/*     */
/* 348 */         com.baomidou.mybatisplus.extension.api.R r = this.memberService.upgrade(order.getUid(), Integer.valueOf(1));
/*     */
/* 350 */         System.out.println(r);
/*     */
/* 352 */         return R.success("退款成功");
/*     */       }
/* 354 */       if (refund.getStatus().equals(Status.CLOSED)) {
/* 355 */         R.fail("退款关闭");
/*     */       }
/* 357 */       else if (refund.getStatus().equals(Status.PROCESSING)) {
/* 358 */         R.fail("退款处理中");
/* 359 */       } else if (refund.getStatus().equals(Status.ABNORMAL)) {
/* 360 */         R.fail("退款异常");
/*     */       }
/*     */
/*     */     }
/* 364 */     catch (ServiceException e) {
/*     */
/* 366 */       System.out.println("捕获微信支付异常");
/* 367 */       System.out.println(e.getResponseBody());
/*     */
/* 369 */       return R.fail("退款异常");
/*     */     }
/*     */
/*     */
/*     */
/*     */
/* 375 */     return R.fail("退款异常");
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\WxtPayServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */