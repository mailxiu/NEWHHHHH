/*    */ package com.bss.sdk;
/*    */ 
/*    */ import com.huifu.bspay.sdk.opps.client.BasePayClient;
/*    */ import com.huifu.bspay.sdk.opps.core.BasePay;
/*    */ import com.huifu.bspay.sdk.opps.core.config.MerConfig;
/*    */ import com.huifu.bspay.sdk.opps.core.request.BaseRequest;
/*    */ import java.io.File;
/*    */ import java.util.Map;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class BaseCommonDemo
/*    */ {
/*    */   public static final String REQUEST_SUCC_CODE = "00000000";
/*    */   
/*    */   public static void doInit(MerConfig merConfig) throws Exception {
/* 23 */     BasePay.initWithMerConfig(merConfig);
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static Map<String, Object> doExecute(BaseRequest request) throws Exception {
/* 33 */     return BasePayClient.request(request, false);
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static Map<String, Object> doExecute(BaseRequest request, boolean isPage) throws Exception {
/* 44 */     return BasePayClient.request(request, isPage);
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static Map<String, Object> doExecute(BaseRequest request, File file) throws Exception {
/* 56 */     return BasePayClient.upload(request, file);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sdk\BaseCommonDemo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */