/*     */ package com.bss.sdk.config;
/*     */ 
/*     */ import java.security.PrivateKey;
/*     */ import java.security.PublicKey;
/*     */ 
/*     */ public class SandPayConfig
/*     */ {
/*     */   private String baseUrl;
/*   9 */   private String version = "4.0.0";
/*     */   private String accessMid;
/*     */   private String plMid;
/*     */   private String mid;
/*     */   private PrivateKey privateKey;
/*     */   private String privateKeyPassword;
/*     */   private String privateKeyPath;
/*     */   private String certNo;
/*     */   private PublicKey sandPublicKey;
/*     */   private String sandPublicKeyPath;
/*  19 */   private String signType = "RSA";
/*  20 */   private String encryptType = "AES";
/*  21 */   private int connectTimeout = 30000;
/*  22 */   private int readTimeout = 30000;
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public String getBaseUrl() {
/*  28 */     return this.baseUrl;
/*     */   }
/*     */   
/*     */   public void setBaseUrl(String baseUrl) {
/*  32 */     this.baseUrl = baseUrl;
/*     */   }
/*     */   
/*     */   public String getVersion() {
/*  36 */     return this.version;
/*     */   }
/*     */   
/*     */   public void setVersion(String version) {
/*  40 */     this.version = version;
/*     */   }
/*     */   
/*     */   public String getAccessMid() {
/*  44 */     return this.accessMid;
/*     */   }
/*     */   
/*     */   public void setAccessMid(String accessMid) {
/*  48 */     this.accessMid = accessMid;
/*     */   }
/*     */   
/*     */   public String getPlMid() {
/*  52 */     return this.plMid;
/*     */   }
/*     */   
/*     */   public void setPlMid(String plMid) {
/*  56 */     this.plMid = plMid;
/*     */   }
/*     */   
/*     */   public String getMid() {
/*  60 */     return this.mid;
/*     */   }
/*     */   
/*     */   public void setMid(String mid) {
/*  64 */     this.mid = mid;
/*     */   }
/*     */   
/*     */   public PrivateKey getPrivateKey() {
/*  68 */     return this.privateKey;
/*     */   }
/*     */   
/*     */   public void setPrivateKey(PrivateKey privateKey) {
/*  72 */     this.privateKey = privateKey;
/*     */   }
/*     */   
/*     */   public String getPrivateKeyPassword() {
/*  76 */     return this.privateKeyPassword;
/*     */   }
/*     */   
/*     */   public void setPrivateKeyPassword(String privateKeyPassword) {
/*  80 */     this.privateKeyPassword = privateKeyPassword;
/*     */   }
/*     */   
/*     */   public String getPrivateKeyPath() {
/*  84 */     return this.privateKeyPath;
/*     */   }
/*     */   
/*     */   public void setPrivateKeyPath(String privateKeyPath) {
/*  88 */     this.privateKeyPath = privateKeyPath;
/*     */   }
/*     */   
/*     */   public String getCertNo() {
/*  92 */     return this.certNo;
/*     */   }
/*     */   
/*     */   public void setCertNo(String certNo) {
/*  96 */     this.certNo = certNo;
/*     */   }
/*     */   
/*     */   public PublicKey getSandPublicKey() {
/* 100 */     return this.sandPublicKey;
/*     */   }
/*     */   
/*     */   public void setSandPublicKey(PublicKey sandPublicKey) {
/* 104 */     this.sandPublicKey = sandPublicKey;
/*     */   }
/*     */   
/*     */   public String getSandPublicKeyPath() {
/* 108 */     return this.sandPublicKeyPath;
/*     */   }
/*     */   
/*     */   public void setSandPublicKeyPath(String sandPublicKeyPath) {
/* 112 */     this.sandPublicKeyPath = sandPublicKeyPath;
/*     */   }
/*     */   
/*     */   public String getSignType() {
/* 116 */     return this.signType;
/*     */   }
/*     */   
/*     */   public void setSignType(String signType) {
/* 120 */     this.signType = signType;
/*     */   }
/*     */   
/*     */   public String getEncryptType() {
/* 124 */     return this.encryptType;
/*     */   }
/*     */   
/*     */   public void setEncryptType(String encryptType) {
/* 128 */     this.encryptType = encryptType;
/*     */   }
/*     */   
/*     */   public int getConnectTimeout() {
/* 132 */     return this.connectTimeout;
/*     */   }
/*     */   
/*     */   public void setConnectTimeout(int connectTimeout) {
/* 136 */     this.connectTimeout = connectTimeout;
/*     */   }
/*     */   
/*     */   public int getReadTimeout() {
/* 140 */     return this.readTimeout;
/*     */   }
/*     */   
/*     */   public void setReadTimeout(int readTimeout) {
/* 144 */     this.readTimeout = readTimeout;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sdk\config\SandPayConfig.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */