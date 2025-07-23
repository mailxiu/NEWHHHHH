/*    */ package com.bss.utils;
/*    */ 
/*    */ import com.alibaba.fastjson.JSONObject;
/*    */ import com.bss.enmus.PayTypeEnum;
/*    */ import java.util.Map;
/*    */ import org.apache.commons.collections4.MapUtils;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class PayTypeExtendUtils
/*    */ {
/*    */   public static String getExtend(String payType, Map<String, Object> extend) {
/* 19 */     System.out.println("传递：" + extend);
/*    */     
/* 21 */     JSONObject json = new JSONObject(3);
/*    */     
/* 23 */     if (PayTypeEnum.wxReplace.equals(payType)) {
/* 24 */       String openid = MapUtils.getString(extend, "openid");
/* 25 */       json.put("openid", openid);
/*    */     } 
/*    */ 
/*    */     
/* 29 */     if (PayTypeEnum.wxCashBonus.equals(payType) || PayTypeEnum.weChatCashBonus.equals(payType)) {
/* 30 */       String openid = MapUtils.getString(extend, "openid");
/* 31 */       String desc = MapUtils.getString(extend, "desc");
/* 32 */       json.put("openid", openid);
/* 33 */       json.put("desc", desc);
/*    */     } 
/*    */ 
/*    */     
/* 37 */     if (PayTypeEnum.wxCashBonus.equals(payType)) {
/* 38 */       String bankName = MapUtils.getString(extend, "bankName");
/* 39 */       String accountName = MapUtils.getString(extend, "accountName");
/* 40 */       String code = MapUtils.getString(extend, "code");
/* 41 */       json.put("bank_name", bankName);
/* 42 */       json.put("account_name", accountName);
/* 43 */       json.put("code", code);
/*    */     } 
/*    */ 
/*    */     
/* 47 */     if (PayTypeEnum.alipayReplace.equals(payType)) {
/* 48 */       String payeeAccount = MapUtils.getString(extend, "payeeAccount");
/* 49 */       json.put("payee_account", payeeAccount);
/*    */     } 
/*    */ 
/*    */     
/* 53 */     if (PayTypeEnum.wxChatH5.equals(payType) || PayTypeEnum.weChatHh5.equals(payType) || PayTypeEnum.weChatJs.equals(payType) || PayTypeEnum.weChatJssh.equals(payType)) {
/* 54 */       String body = MapUtils.getString(extend, "body");
/* 55 */       json.put("body", body);
/*    */     } 
/*    */ 
/*    */     
/* 59 */     if (PayTypeEnum.wxrequestPayment.equals(payType)) {
/* 60 */       String gname = MapUtils.getString(extend, "gname");
/* 61 */       String jsCode = MapUtils.getString(extend, "jsCode");
/* 62 */       json.put("gname", gname);
/* 63 */       json.put("js_code", jsCode);
/*    */     } 
/*    */     
/* 66 */     System.out.println(payType);
/*    */ 
/*    */     
/* 69 */     if (PayTypeEnum.BFWechatXcxZY.name().equals(payType)) {
/* 70 */       System.out.println("解析参数");
/* 71 */       String body = MapUtils.getString(extend, "body");
/* 72 */       String openid = MapUtils.getString(extend, "openid");
/* 73 */       json.put("body", body);
/* 74 */       json.put("openid", openid);
/*    */     } 
/*    */ 
/*    */     
/* 78 */     if (PayTypeEnum.weChatNative.equals(payType) || PayTypeEnum.weChatNativesh.equals(payType));
/*    */ 
/*    */ 
/*    */     
/* 82 */     if (PayTypeEnum.alipayApp.equals(payType) || PayTypeEnum.alipayPrecreate.equals(payType) || PayTypeEnum.alipayPcWebPay
/* 83 */       .equals(payType) || PayTypeEnum.alipayWapPay.equals(payType)) {
/* 84 */       String subject = MapUtils.getString(extend, "subject");
/* 85 */       json.put("subject", subject);
/*    */     } 
/* 87 */     if (json.isEmpty()) {
/* 88 */       return null;
/*    */     }
/* 90 */     return json.toJSONString();
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\PayTypeExtendUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */