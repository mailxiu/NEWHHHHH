/*    */ package com.bss.sdk.exception;
/*    */ 
/*    */ import com.alibaba.fastjson.JSON;
/*    */ import com.alibaba.fastjson.JSONObject;
/*    */ 
/*    */ public class SandPayException
/*    */   extends RuntimeException
/*    */ {
/*    */   private String respCode;
/*    */   private String respDesc;
/*    */   private String responseMsg;
/*    */   
/*    */   public SandPayException() {}
/*    */   
/*    */   public SandPayException(String message) {
/* 16 */     super(message);
/* 17 */     this.respDesc = message;
/*    */   }
/*    */   
/*    */   public SandPayException(String message, Throwable cause) {
/* 21 */     super(message, cause);
/* 22 */     this.respDesc = message;
/*    */   }
/*    */   
/*    */   public SandPayException(String respCode, String respDesc, String responseMsg) {
/* 26 */     super(respCode + ":" + respDesc);
/* 27 */     this.respCode = respCode;
/* 28 */     this.respDesc = respDesc;
/* 29 */     this.responseMsg = responseMsg;
/*    */   }
/*    */   
/*    */   public String toString() {
/* 33 */     return toJSON().toString();
/*    */   }
/*    */   
/*    */   public JSONObject toJSON() {
/* 37 */     JSONObject sandResp = new JSONObject();
/* 38 */     sandResp.put("respCode", getRespCode());
/* 39 */     sandResp.put("respDesc", getRespDesc());
/* 40 */     if (getResponseMsg() != null && getResponseMsg().length() > 0) {
/* 41 */       JSONObject responseMsg = (JSONObject)JSON.parseObject(getResponseMsg(), JSONObject.class);
/* 42 */       sandResp.put("responseMsg", responseMsg);
/*    */     } 
/*    */     
/* 45 */     return sandResp;
/*    */   }
/*    */   
/*    */   public String getRespCode() {
/* 49 */     return this.respCode;
/*    */   }
/*    */   
/*    */   public String getRespDesc() {
/* 53 */     return this.respDesc;
/*    */   }
/*    */   
/*    */   public String getResponseMsg() {
/* 57 */     return this.responseMsg;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sdk\exception\SandPayException.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */