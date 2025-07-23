/*     */ package com.bss.sdk.utils;
/*     */ 
/*     */ import com.bss.sdk.exception.SandPayException;
/*     */
/*     */
/*     */ import java.io.InputStream;
/*     */ import java.security.PrivateKey;
/*     */ import java.security.PublicKey;
/*     */ import java.util.Objects;
/*     */ import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ 
/*     */ public class SandpayConfigUtil {
/*  14 */   public static final Logger logger = LoggerFactory.getLogger(com.bss.sdk.utils.SandpayConfigUtil.class);
/*     */   private String baseUrl;
/*     */   private String version;
/*     */   private String accessMid;
/*     */   private String plMid;
/*     */   private String mid;
/*     */   private PrivateKey privateKey;
/*     */   private String certNo;
/*     */   private PublicKey sandPublicKey;
/*  23 */   private String signType = "SHA256WithRSA";
/*  24 */   private String encryptType = "AES";
/*  25 */   private int connectTimeout = 10000;
/*  26 */   private int readTimeout = 10000;
/*     */   
/*     */   public static final String CHARSET = "UTF-8";
/*     */   
/*     */   public static final String AES_STR = "AES";
/*     */   
/*     */   public static final String RSA_STR = "RSA";
/*     */   public static final String SHA_256_WITH_RSA = "SHA256WithRSA";
/*     */   public static final String SUCCESS_STR = "success";
/*     */   public static final String RESP_CODE_STR = "respCode";
/*     */   public static final String RESP_DESC_STR = "respDesc";
/*     */   public static final String BIZ_DATA_STR = "bizData";
/*     */   public static final String SIGN_STR = "sign";
/*     */   public static final String SIGN_TYPE_STR = "signType";
/*     */   public static final String ENCRYPT_TYPE_STR = "encryptType";
/*     */   public static final String ENCRYPT_KEY_STR = "encryptKey";
/*     */   
/*     */   public PrivateKey getPrivateKey(String privateKeyPath, String privateKeyPassword) throws Exception {
/*  44 */     logger.debug("商户私钥路径 => " + privateKeyPath);
/*  45 */     logger.debug("商户私钥密码 => " + privateKeyPassword);
/*  46 */     InputStream privateIns = FileUtils.loadFile(privateKeyPath);
/*  47 */     if (Objects.isNull(privateIns)) {
/*  48 */       throw new SandPayException("获取私钥失败");
/*     */     }
/*  50 */     return RSAUtils.loadPrivateKey(privateIns, privateKeyPassword);
/*     */   }
/*     */ 
/*     */   
/*     */   public PublicKey getSandPublicKey(String sandPublicKeyPath) throws Exception {
/*  55 */     logger.debug("杉德公钥路径 => " + sandPublicKeyPath);
/*  56 */     InputStream publicIns = FileUtils.loadFile(sandPublicKeyPath);
/*  57 */     if (Objects.isNull(publicIns)) {
/*  58 */       throw new SandPayException("获取公钥失败");
/*     */     }
/*  60 */     return RSAUtils.loadPublicKey(publicIns);
/*     */   }
/*     */ 
/*     */   
/*     */   public String getBaseUrl() {
/*  65 */     return this.baseUrl;
/*     */   }
/*     */   
/*     */   public void setBaseUrl(String baseUrl) {
/*  69 */     this.baseUrl = baseUrl;
/*     */   }
/*     */   
/*     */   public String getVersion() {
/*  73 */     return this.version;
/*     */   }
/*     */   
/*     */   public void setVersion(String version) {
/*  77 */     this.version = version;
/*     */   }
/*     */   
/*     */   public String getAccessMid() {
/*  81 */     return this.accessMid;
/*     */   }
/*     */   
/*     */   public void setAccessMid(String accessMid) {
/*  85 */     this.accessMid = accessMid;
/*     */   }
/*     */   
/*     */   public String getPlMid() {
/*  89 */     return this.plMid;
/*     */   }
/*     */   
/*     */   public void setPlMid(String plMid) {
/*  93 */     this.plMid = plMid;
/*     */   }
/*     */   
/*     */   public String getMid() {
/*  97 */     return this.mid;
/*     */   }
/*     */   
/*     */   public void setMid(String mid) {
/* 101 */     this.mid = mid;
/*     */   }
/*     */   
/*     */   public PrivateKey getPrivateKey() {
/* 105 */     return this.privateKey;
/*     */   }
/*     */   
/*     */   public void setPrivateKey(PrivateKey privateKey) {
/* 109 */     this.privateKey = privateKey;
/*     */   }
/*     */   
/*     */   public String getCertNo() {
/* 113 */     return this.certNo;
/*     */   }
/*     */   
/*     */   public void setCertNo(String certNo) {
/* 117 */     this.certNo = certNo;
/*     */   }
/*     */   
/*     */   public PublicKey getSandPublicKey() {
/* 121 */     return this.sandPublicKey;
/*     */   }
/*     */   
/*     */   public void setSandPublicKey(PublicKey sandPublicKey) {
/* 125 */     this.sandPublicKey = sandPublicKey;
/*     */   }
/*     */   
/*     */   public String getSignType() {
/* 129 */     return this.signType;
/*     */   }
/*     */   
/*     */   public void setSignType(String signType) {
/* 133 */     this.signType = signType;
/*     */   }
/*     */   
/*     */   public String getEncryptType() {
/* 137 */     return this.encryptType;
/*     */   }
/*     */   
/*     */   public void setEncryptType(String encryptType) {
/* 141 */     this.encryptType = encryptType;
/*     */   }
/*     */   
/*     */   public int getConnectTimeout() {
/* 145 */     return this.connectTimeout;
/*     */   }
/*     */   
/*     */   public void setConnectTimeout(int connectTimeout) {
/* 149 */     this.connectTimeout = connectTimeout;
/*     */   }
/*     */   
/*     */   public int getReadTimeout() {
/* 153 */     return this.readTimeout;
/*     */   }
/*     */   
/*     */   public void setReadTimeout(int readTimeout) {
/* 157 */     this.readTimeout = readTimeout;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\SandpayConfigUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */