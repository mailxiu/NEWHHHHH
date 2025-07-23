/*     */ package com.bss.sdk;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.bss.sdk.config.SandPayConfig;
/*     */ import com.bss.sdk.exception.SandPayException;
/*     */ import com.bss.sdk.utils.AESUtils;
/*     */ import com.bss.sdk.utils.HttpClientUtils;
/*     */ import com.bss.sdk.utils.RSAUtils;
/*     */ import com.bss.sdk.utils.SandpayConfigUtil;
/*     */ import com.bss.sdk.utils.StringUtils;
/*     */ import java.nio.charset.StandardCharsets;
/*     */ import java.security.PrivateKey;
/*     */ import java.security.PublicKey;
/*     */ import java.text.DateFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import java.util.Date;
/*     */ import java.util.Objects;
/*     */ import java.util.TimeZone;
/*     */ import org.apache.tomcat.util.codec.binary.Base64;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.stereotype.Component;
/*     */ 
/*     */ @Component
/*     */ public class SandPayClient
/*     */ {
/*  29 */   private static final Logger log = LoggerFactory.getLogger(com.bss.sdk.SandPayClient.class);
/*     */ 
/*     */ 
/*     */   
/*  33 */   private SandpayConfigUtil sandpayConfigUtil = new SandpayConfigUtil();
/*     */ 
/*     */   
/*     */   public SandPayClient() {}
/*     */   
/*     */   public SandPayClient(SandPayConfig sandPayConfig) {
/*  39 */     if (sandPayConfig != null) {
/*     */       try {
/*  41 */         this.sandpayConfigUtil.setBaseUrl(sandPayConfig.getBaseUrl());
/*  42 */         this.sandpayConfigUtil.setAccessMid(sandPayConfig.getAccessMid());
/*  43 */         this.sandpayConfigUtil.setMid(sandPayConfig.getMid());
/*  44 */         this.sandpayConfigUtil.setPlMid(sandPayConfig.getPlMid());
/*  45 */         this.sandpayConfigUtil.setVersion(sandPayConfig.getVersion());
/*     */         
/*  47 */         String privateKeyPath = sandPayConfig.getPrivateKeyPath();
/*  48 */         String sandPublicKeyPath = sandPayConfig.getSandPublicKeyPath();
/*  49 */         if (!StringUtils.isBlank(privateKeyPath) || !StringUtils.isBlank(sandPublicKeyPath)) {
/*  50 */           this.sandpayConfigUtil.setPrivateKey(this.sandpayConfigUtil.getPrivateKey(sandPayConfig.getPrivateKeyPath(), sandPayConfig.getPrivateKeyPassword()));
/*  51 */           this.sandpayConfigUtil.setSandPublicKey(this.sandpayConfigUtil.getSandPublicKey(sandPayConfig.getSandPublicKeyPath()));
/*  52 */           this.sandpayConfigUtil.setEncryptType(sandPayConfig.getEncryptType());
/*  53 */           this.sandpayConfigUtil.setSignType(sandPayConfig.getSignType());
/*  54 */           Integer connectTimeout = Integer.valueOf(sandPayConfig.getConnectTimeout());
/*  55 */           if (Objects.nonNull(connectTimeout)) {
/*  56 */             this.sandpayConfigUtil.setConnectTimeout(connectTimeout.intValue());
/*     */           }
/*     */           
/*  59 */           Integer readTimeout = Integer.valueOf(sandPayConfig.getReadTimeout());
/*  60 */           if (Objects.nonNull(readTimeout)) {
/*  61 */             this.sandpayConfigUtil.setReadTimeout(readTimeout.intValue());
/*     */           }
/*     */         }
/*     */       
/*  65 */       } catch (Exception var6) {
/*  66 */         log.error(var6.getMessage());
/*  67 */         throw new SandPayException("初始化SandPayClient异常", var6);
/*     */       } 
/*     */     }
/*     */   }
/*     */   
/*     */   public JSONObject execute(String url, JSONObject bizData) {
/*  73 */     return requestCoreReturnObject(url, bizData, JSONObject.class);
/*     */   }
/*     */   
/*     */   public JSONObject execute(String url, JSONObject bizData, String encryptType) {
/*  77 */     return requestCoreReturnObject(url, bizData, JSONObject.class, encryptType);
/*     */   }
/*     */   
/*     */   private <T> T requestCoreReturnObject(String url, Object bizRequest, Class<T> returnClass, String encryptType) {
/*  81 */     String bizRequestJson = JSON.toJSONString(bizRequest);
/*  82 */     JSONObject sandPayCommonRequest = buildRequest(bizRequestJson, encryptType);
/*     */     
/*  84 */     String responseStr = HttpClientUtils.sendPost(url, JSON.toJSONString(sandPayCommonRequest), this.sandpayConfigUtil.getConnectTimeout(), this.sandpayConfigUtil.getReadTimeout());
/*     */     
/*  86 */     return handleResponse(responseStr, returnClass, encryptType);
/*     */   }
/*     */   
/*     */   private <T> T requestCoreReturnObject(String url, Object bizRequest, Class<T> returnClass) throws SandPayException {
/*  90 */     String encryptType = this.sandpayConfigUtil.getEncryptType();
/*  91 */     return requestCoreReturnObject(url, bizRequest, returnClass, encryptType);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public JSONObject buildRequest(String content, String encryptType) throws SandPayException {
/* 101 */     String signType = "RSA";
/*     */ 
/*     */ 
/*     */     
/* 105 */     if (StringUtils.isBlank(content))
/* 106 */       throw new SandPayException("签名内容为空 : content=" + content); 
/* 107 */     if (!"AES".equals(encryptType)) {
/* 108 */       throw new SandPayException("不是支持的加密类型 : encryptType=" + encryptType);
/*     */     }
/*     */ 
/*     */     
/* 112 */     String aesKey = StringUtils.genRandomString(16);
/*     */ 
/*     */ 
/*     */     
/* 116 */     String bizData = aesEncrypt(content, aesKey);
/*     */ 
/*     */     
/* 119 */     String encryptKey = rsaEncrypt(aesKey, this.sandpayConfigUtil.getSandPublicKey());
/*     */ 
/*     */     
/* 122 */     String sign = generateSign(bizData, signType, this.sandpayConfigUtil.getPrivateKey());
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 127 */     JSONObject commonRequest = new JSONObject();
/* 128 */     commonRequest.put("accessMid", this.sandpayConfigUtil.getAccessMid());
/* 129 */     commonRequest.put("encryptType", encryptType);
/* 130 */     commonRequest.put("encryptKey", encryptKey);
/*     */     
/* 132 */     commonRequest.put("version", this.sandpayConfigUtil.getVersion());
/* 133 */     commonRequest.put("timestamp", getTimestamp());
/* 134 */     commonRequest.put("signType", signType);
/* 135 */     commonRequest.put("sign", sign);
/* 136 */     commonRequest.put("bizData", bizData);
/* 137 */     return commonRequest;
/*     */   }
/*     */ 
/*     */   
/*     */   public JSONObject parseResponse(String content, String encryptType) throws SandPayException {
/* 142 */     return handleResponse(content, JSONObject.class, encryptType);
/*     */   }
/*     */ 
/*     */   
/*     */   public boolean verifySign(String data, String sign, String signType, String charset) throws SandPayException {
/*     */     try {
/* 148 */       return RSAUtils.verifySign(data, sign, signType, this.sandpayConfigUtil.getSandPublicKey(), charset);
/* 149 */     } catch (Exception var6) {
/* 150 */       throw new SandPayException("验证回调签名异常", var6);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private <T> T handleResponse(String responseStr, Class<T> returnClass, String encryptType) throws SandPayException {
/* 156 */     JSONObject commonResponse = (JSONObject)JSON.parseObject(responseStr, JSONObject.class);
/* 157 */     String respCode = (String)commonResponse.get("respCode");
/* 158 */     if (respCode == null) {
/* 159 */       throw new SandPayException("处理返回报文失败,原始报文" + responseStr);
/*     */     }
/*     */     
/* 162 */     if (!"success".equals(respCode)) {
/* 163 */       String str = (String)commonResponse.get("respDesc");
/* 164 */       throw new SandPayException(respCode, str, responseStr);
/*     */     } 
/* 166 */     String bizData = commonResponse.get("bizData").toString();
/* 167 */     String sign = (String)commonResponse.get("sign");
/* 168 */     String signType = (String)commonResponse.get("signType");
/* 169 */     verifySign(bizData, sign, signType, this.sandpayConfigUtil.getSandPublicKey());
/* 170 */     if (!"AES".equals(encryptType)) {
/* 171 */       throw new SandPayException("不是支持的加密类型: encryptType=" + encryptType);
/*     */     }
/* 173 */     String encryptKey = (String)commonResponse.get("encryptKey");
/* 174 */     String respAesKey = rsaDecrypt(encryptKey, this.sandpayConfigUtil.getPrivateKey());
/* 175 */     bizData = aesDecrypt(bizData, respAesKey);
/*     */     
/* 177 */     if (returnClass == String.class) {
/* 178 */       return (T)bizData;
/*     */     }
/*     */     try {
/* 181 */       return (T)JSON.parseObject(bizData, returnClass);
/* 182 */     } catch (Exception var11) {
/* 183 */       throw new SandPayException("解析报文失败," + responseStr, var11);
/*     */     } 
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   private String aesEncrypt(String content, String aesKey) {
/* 193 */     byte[] aesKeyBytes = aesKey.getBytes(StandardCharsets.UTF_8);
/*     */     
/*     */     try {
/* 196 */       byte[] encryptValueBytes = AESUtils.encrypt(content.getBytes(StandardCharsets.UTF_8), aesKeyBytes, (String)null);
/* 197 */       return Base64.encodeBase64String(encryptValueBytes);
/* 198 */     } catch (Exception var5) {
/* 199 */       throw new SandPayException("AES加密异常", var5);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   public static String rsaEncrypt(String content, PublicKey publicKey) {
/*     */     try {
/* 206 */       byte[] aesKeyBytes = content.getBytes();
/* 207 */       byte[] encryptKeyBytes = RSAUtils.encrypt(aesKeyBytes, publicKey);
/* 208 */       return Base64.encodeBase64String(encryptKeyBytes);
/* 209 */     } catch (Exception var4) {
/* 210 */       throw new SandPayException("RSA加密异常", var4);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private String rsaDecrypt(String content, PrivateKey privateKey) {
/* 216 */     byte[] decryptKeyBytes = Base64.decodeBase64(content);
/*     */     
/*     */     try {
/* 219 */       byte[] contentBytes = RSAUtils.decrypt(decryptKeyBytes, privateKey);
/* 220 */       String decryptKey = new String(contentBytes, StandardCharsets.UTF_8);
/* 221 */       return decryptKey;
/* 222 */     } catch (Exception var6) {
/* 223 */       throw new SandPayException("RSA解密随机加密串失败", var6);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private String aesDecrypt(String content, String aesKey) {
/* 229 */     byte[] decryptDataBase64 = Base64.decodeBase64(content);
/*     */     
/*     */     try {
/* 232 */       byte[] decryptDataBytes = AESUtils.decrypt(decryptDataBase64, aesKey.getBytes(StandardCharsets.UTF_8), (String)null);
/* 233 */       String decryptData = new String(decryptDataBytes);
/* 234 */       return decryptData;
/* 235 */     } catch (Exception var6) {
/* 236 */       throw new SandPayException("AES解密返回参数失败", var6);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   public String generateSign(String content, String signType, PrivateKey privateKey) {
/*     */     try {
/* 243 */       if ("RSA".equals(signType)) {
/* 244 */         signType = "SHA256WithRSA";
/*     */       }
/*     */       
/* 247 */       return RSAUtils.generateSign(content, privateKey, signType, "UTF-8");
/* 248 */     } catch (Exception var5) {
/* 249 */       throw new SandPayException("请求签名异常", var5);
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
/*     */   private boolean verifySign(String content, String sign, String signType, PublicKey publicKey) {
/*     */     try {
/* 263 */       if ("RSA".equals(signType)) {
/* 264 */         signType = "SHA256WithRSA";
/*     */       }
/* 266 */       return RSAUtils.verifySign(content, sign, signType, publicKey, "UTF-8");
/* 267 */     } catch (Exception var6) {
/* 268 */       throw new SandPayException("验证响应报文签名异常", var6);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private String getTimestamp() {
/* 274 */     DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/* 275 */     df.setTimeZone(TimeZone.getTimeZone("GMT+8"));
/* 276 */     return df.format(new Date(System.currentTimeMillis()));
/*     */   }
/*     */ 
/*     */   
/*     */   public String getCurrentTime() {
/* 281 */     SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
/* 282 */     sdf.setTimeZone(TimeZone.getTimeZone("GMT+8"));
/* 283 */     return sdf.format(new Date());
/*     */   }
/*     */ 
/*     */   
/*     */   public String getTimeOutTime(int hour) {
/* 288 */     Calendar calendar = Calendar.getInstance();
/* 289 */     calendar.add(10, hour);
/* 290 */     SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
/* 291 */     sdf.setTimeZone(TimeZone.getTimeZone("GMT+8"));
/* 292 */     return sdf.format(calendar.getTime());
/*     */   }
/*     */ 
/*     */   
/*     */   public String getOutOrderNo() {
/* 297 */     return getOutOrderNo("", 25);
/*     */   }
/*     */   
/*     */   public String getOutOrderNo(String prefix, int length) {
/* 301 */     if (prefix == null) {
/* 302 */       prefix = "";
/*     */     }
/*     */     
/* 305 */     if (length < 25) {
/* 306 */       length = 25;
/*     */     }
/*     */     
/* 309 */     DateFormat df = new SimpleDateFormat("yyyyMMddHHmmsss");
/* 310 */     df.setTimeZone(TimeZone.getTimeZone("GMT+8"));
/* 311 */     String currentTime = df.format(new Date(System.currentTimeMillis()));
/* 312 */     String outOrderNo = prefix.concat(currentTime);
/* 313 */     int randomLen = length - outOrderNo.length();
/* 314 */     outOrderNo = prefix.concat(currentTime).concat(StringUtils.genRandomNumber(randomLen));
/* 315 */     return outOrderNo;
/*     */   }
/*     */   
/*     */   public SandpayConfigUtil getSandpayConfigUtil() {
/* 319 */     return this.sandpayConfigUtil;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sdk\SandPayClient.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */