/*     */ package com.bss.service.impl;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.Order;
/*     */ import com.bss.sdk.BaseCommonDemo;
/*     */ import com.bss.sdk.core.Identify;
/*     */
/*     */ import com.bss.utils.R;
/*     */ import com.huifu.bspay.sdk.opps.core.BasePay;
/*     */ import com.huifu.bspay.sdk.opps.core.config.MerConfig;
/*     */ import com.huifu.bspay.sdk.opps.core.net.BasePayRequest;
/*     */ import com.huifu.bspay.sdk.opps.core.request.V2TradeOnlinepaymentQuickpayPageinfoRequest;
/*     */ import com.huifu.bspay.sdk.opps.core.utils.DateTools;
/*     */ import java.util.HashMap;
/*     */ import java.util.Map;
/*     */ import javax.annotation.Resource;
/*     */ import org.springframework.stereotype.Service;
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
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ @Identify(requestClass = V2TradeOnlinepaymentQuickpayPageinfoRequest.class)
/*     */ @Service
/*     */ public class HuiFuPayServiceImp
/*     */   extends BaseCommonDemo
/*     */ {
/*     */   public static final String DEMO_PRODUCT_ID = "EDUSTD";
/*     */   public static final String DEMO_SYS_ID = "6666000166606037";
/*     */   public static final String DEMO_HUIFU_ID = "6666000166606037";
/*     */   public static final String DEMO_RSA_PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCbmkGwbVvKyEEmsNkZrI2H23qlSY1oPMhph4P24xFchlgOLnK8hvKcLM10snF3w/u371UNra58u39E9ocU6lNiGkRzfn0FvG3Pf0xIM6Xzu39SJP2kohbRHnfO5vda5gg1RHX36eH63JvBV3X9FfbAoKVC5h3aZavHFldDgGD6dnIwFUOhLP8emt5Kxti+x96U8vQcjyHko23ACxZm2tqIzcwtxNdFG4nhqCq0Pxwf3FFuOBCCrWALi0lIWp6mzHjSPiKvHFrlvc/nFuskGo7e3A5vKeXeHUw7pi0AyCIuu+ZCJCOE1kBknh0mifGxaPHq9krNSuPUz+a3f0kIWEpXAgMBAAECggEAKYMBu1uxfWvnVbcgdCUArRn0olv5CbINlXm9zwPNAe4lV8M0gO9PkjKxrUxd0SHL6cpD2p5XSpeK4I8UgpPxIt73HAjGud0HPrArXafJwjhnQzbzJBTKGYgTVnNv0iREVFGrVzRiQVbRhscahyZw6frxm+NgW398UGS5axy4wpijgDyFarSJVafdV888fTPfUVo9L2IX5xQ866FxN5PNxJL84PzFFozWYNfHLcs54jJ8/zuqwtK+t0IbB/l3oHcnuK0Sfy8oWLg25FPZxlmDh9XG5eyEkzM3AeHATwj7BPAtA/G1LAF+cnxutGMv1LzxvJB4YEkWYV0zErOCWlGCIQKBgQDjW67SGbsMUAiEaYEs/LbapPs2C3eSe7W2VcOAEnmXW+/j2nbjlT8az3XyHaAca7xnQMreQsP2Utfe9JCFf2qngISBTfMjrb6YUPgIaww/pUKKov5+zQl1jR1isuvpkUGXeWu2fEfbGUT7Lf6gSB0wIkXBigaRHnhgnOgBEkFujQKBgQCvNHN62ko9J+27SHXPL2hGGeEoG/8H3eLwo0pE2MlvVHKXCJs7JlDLaG9dlIk3YXrh5OjrwY8ULuDylY3He2Lef91tbRWpMYvYHOdVIdgbUGwGs3ZkM3W7UIWYc48dpVZvhY/ScqRhmtdUNcdJzHCeVAx5Uj0jh35oD13egy5lcwKBgQDH2QRPbAyt4v/JnI/Ogokcod6rf+LoINP2ZWbGgfbdZBP2vka4/6yLnYa4fvAJa24deKeaPSfRsrpMIb+TiQ+wEtjmbCVn3EZnzuxnQelvXI2kHWgE/6fr61HEOzABjAwS4MkcjBwBbDHldGWYcCsv70BPwkrJbvYzPlj08B4R1QKBgCRqrI4ejUvE3t8MoqAb5HqdqnUhzJKgBimqZyeEP+pKDT9jZJCY2DZPUMaMtzCxrE8Du341Tz4MuGjzuPJ7rQM+ZJH4GIaAa+bRqyvAyyBySOHjr3oIUDJM/FfBvT+WPC8V/dzqQ0yeWJ+CRhgKzGW8ZpNZCqg144pRl1tGvQANAoGBAI9aVVexbHCrfdyIcdBLcI6xIly+geDyws8l/a4N6PXmVs4q+gYTyMOSrYA+DBSadCna+26+h8vGubl68Rtj0YkZ4+Yn+WpMHORI5z+Q2EBzS/03Gz9ByFEa4gE9ggraURMqhdeddcXVvgcPlAOl+UMTqOvPyp1sIwHugzPU4Aiw";
/*     */   public static final String DEMO_RSA_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJAKwd9m7ZeTJAUnRb44I3LcmBzspqtXqCULL+7LoQirD1+X1nK+i7UoOadZ0ev64B/60clkftU8PU1tnCyPCABUlLl6QGCRDl+dvVPPiCHtJE37DbQQbUh6acrW+lo3HlM0SNHVH05grrun5EuWLYFusS+UjNDA0gbjaygdK3ONxrfvo4qrB6mSAoxLkqya/rU/7TYqa5o7BlhkTmtbcl8shzgY0sqtBMmVeE0cSSmaWN8crTR5F36sIBcQ50RPpRT4KEWyP/MMM65UhHTT80U7pnxZKQD1+s5rmHIwc9px/l2mMGQkrvWvrCNobfFJ5o1Z0r4NqQa8SG/jSTAKDQIDAQAB";
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */   
/*     */   public R huiFuQuickPayment(String oid) throws Exception {
/*  69 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */ 
/*     */     
/*  72 */     MerConfig merConfig = new MerConfig();
/*  73 */     merConfig.setProcutId("EDUSTD");
/*  74 */     merConfig.setSysId("6666000166606037");
/*  75 */     merConfig.setRsaPrivateKey("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCbmkGwbVvKyEEmsNkZrI2H23qlSY1oPMhph4P24xFchlgOLnK8hvKcLM10snF3w/u371UNra58u39E9ocU6lNiGkRzfn0FvG3Pf0xIM6Xzu39SJP2kohbRHnfO5vda5gg1RHX36eH63JvBV3X9FfbAoKVC5h3aZavHFldDgGD6dnIwFUOhLP8emt5Kxti+x96U8vQcjyHko23ACxZm2tqIzcwtxNdFG4nhqCq0Pxwf3FFuOBCCrWALi0lIWp6mzHjSPiKvHFrlvc/nFuskGo7e3A5vKeXeHUw7pi0AyCIuu+ZCJCOE1kBknh0mifGxaPHq9krNSuPUz+a3f0kIWEpXAgMBAAECggEAKYMBu1uxfWvnVbcgdCUArRn0olv5CbINlXm9zwPNAe4lV8M0gO9PkjKxrUxd0SHL6cpD2p5XSpeK4I8UgpPxIt73HAjGud0HPrArXafJwjhnQzbzJBTKGYgTVnNv0iREVFGrVzRiQVbRhscahyZw6frxm+NgW398UGS5axy4wpijgDyFarSJVafdV888fTPfUVo9L2IX5xQ866FxN5PNxJL84PzFFozWYNfHLcs54jJ8/zuqwtK+t0IbB/l3oHcnuK0Sfy8oWLg25FPZxlmDh9XG5eyEkzM3AeHATwj7BPAtA/G1LAF+cnxutGMv1LzxvJB4YEkWYV0zErOCWlGCIQKBgQDjW67SGbsMUAiEaYEs/LbapPs2C3eSe7W2VcOAEnmXW+/j2nbjlT8az3XyHaAca7xnQMreQsP2Utfe9JCFf2qngISBTfMjrb6YUPgIaww/pUKKov5+zQl1jR1isuvpkUGXeWu2fEfbGUT7Lf6gSB0wIkXBigaRHnhgnOgBEkFujQKBgQCvNHN62ko9J+27SHXPL2hGGeEoG/8H3eLwo0pE2MlvVHKXCJs7JlDLaG9dlIk3YXrh5OjrwY8ULuDylY3He2Lef91tbRWpMYvYHOdVIdgbUGwGs3ZkM3W7UIWYc48dpVZvhY/ScqRhmtdUNcdJzHCeVAx5Uj0jh35oD13egy5lcwKBgQDH2QRPbAyt4v/JnI/Ogokcod6rf+LoINP2ZWbGgfbdZBP2vka4/6yLnYa4fvAJa24deKeaPSfRsrpMIb+TiQ+wEtjmbCVn3EZnzuxnQelvXI2kHWgE/6fr61HEOzABjAwS4MkcjBwBbDHldGWYcCsv70BPwkrJbvYzPlj08B4R1QKBgCRqrI4ejUvE3t8MoqAb5HqdqnUhzJKgBimqZyeEP+pKDT9jZJCY2DZPUMaMtzCxrE8Du341Tz4MuGjzuPJ7rQM+ZJH4GIaAa+bRqyvAyyBySOHjr3oIUDJM/FfBvT+WPC8V/dzqQ0yeWJ+CRhgKzGW8ZpNZCqg144pRl1tGvQANAoGBAI9aVVexbHCrfdyIcdBLcI6xIly+geDyws8l/a4N6PXmVs4q+gYTyMOSrYA+DBSadCna+26+h8vGubl68Rtj0YkZ4+Yn+WpMHORI5z+Q2EBzS/03Gz9ByFEa4gE9ggraURMqhdeddcXVvgcPlAOl+UMTqOvPyp1sIwHugzPU4Aiw");
/*  76 */     merConfig.setRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJAKwd9m7ZeTJAUnRb44I3LcmBzspqtXqCULL+7LoQirD1+X1nK+i7UoOadZ0ev64B/60clkftU8PU1tnCyPCABUlLl6QGCRDl+dvVPPiCHtJE37DbQQbUh6acrW+lo3HlM0SNHVH05grrun5EuWLYFusS+UjNDA0gbjaygdK3ONxrfvo4qrB6mSAoxLkqya/rU/7TYqa5o7BlhkTmtbcl8shzgY0sqtBMmVeE0cSSmaWN8crTR5F36sIBcQ50RPpRT4KEWyP/MMM65UhHTT80U7pnxZKQD1+s5rmHIwc9px/l2mMGQkrvWvrCNobfFJ5o1Z0r4NqQa8SG/jSTAKDQIDAQAB");
/*  77 */     BasePay.initWithMerConfig(merConfig);
/*     */     
/*  79 */     Map<String, Object> paramsInfo = new HashMap<>();
/*     */     
/*  81 */     paramsInfo.put("req_seq_id", order.getOid());
/*     */     
/*  83 */     paramsInfo.put("req_date", DateTools.getCurrentDateYYYYMMDD());
/*     */     
/*  85 */     paramsInfo.put("huifu_id", "6666000166606037");
/*     */     
/*  87 */     paramsInfo.put("trans_amt", order.getMoney());
/*     */     
/*  89 */     paramsInfo.put("extend_pay_data", "{\"goods_short_name\":\"01\",\"biz_tp\":\"123451\",\"gw_chnnl_tp\":\"02\"}");
/*     */     
/*  91 */     paramsInfo.put("terminal_device_data", "{\"device_type\":\"1\",\"device_ip\":\"127.0.0.1\"}");
/*     */     
/*  93 */     paramsInfo.put("risk_check_data", "{\"ip_addr\":\"127.0.0.1\"}");
/*     */     
/*  95 */     paramsInfo.put("notify_url", "https://hs.mailxiu.com/huiFuPay/payNotify");
/*     */     
/*  97 */     paramsInfo.put("order_type", "P");
/*     */     
/*  99 */     paramsInfo.put("goods_desc", "服务费缴纳");
/*     */     
/* 101 */     paramsInfo.put("request_type", "M");
/*     */ 
/*     */ 
/*     */     
/* 105 */     paramsInfo.put("fee_flag", "2");
/*     */     
/* 107 */     paramsInfo.put("remark", "服务费缴纳");
/*     */     
/* 109 */     paramsInfo.put("front_url", "https://hs.mailxiu.com/open/huiFuTransfer");
/*     */     
/* 111 */     Map<String, Object> response = BasePayRequest.requestBasePay("v2/trade/onlinepayment/quickpay/frontpay", paramsInfo, null, false);
/*     */ 
/*     */     
/* 114 */     if (response.get("resp_code").equals("00000000"))
/*     */     {
/*     */       
/* 117 */       return R.success(response.get("form_url"));
/*     */     }
/*     */ 
/*     */     
/* 121 */     return R.fail(response.get("resp_desc").toString());
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\HuiFuPayServiceImp.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */