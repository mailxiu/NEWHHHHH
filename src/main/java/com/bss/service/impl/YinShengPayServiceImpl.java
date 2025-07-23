/*     */ package com.bss.service.impl;
/*     */ 
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.enmus.PayTypeEnum;
/*     */ import com.bss.entity.Order;
/*     */
/*     */ import com.bss.utils.HttpUtils;
/*     */ import com.bss.utils.PayTypeExtendUtils;
/*     */ import com.bss.utils.R;
/*     */ import com.bss.utils.SignUtils;
/*     */ import java.text.DecimalFormat;
/*     */ import java.util.HashMap;
/*     */ import java.util.Map;
/*     */ import javax.annotation.Resource;
/*     */ import org.apache.commons.collections4.MapUtils;
/*     */ import org.springframework.stereotype.Service;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
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
/*     */ @Service
/*     */ public class YinShengPayServiceImpl
/*     */ {
/*     */   @Resource
/*     */   private OrderServiceImpl orderService;
/*     */   
/*     */   public R goYinShengPay(String oid) {
/*  52 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/*  54 */     DecimalFormat df = new DecimalFormat("#.00");
/*     */     
/*  56 */     Map<String, Object> payMap = new HashMap<>(10);
/*  57 */     payMap.put("payType", PayTypeEnum.YSWxXcxPay);
/*  58 */     Map<String, Object> extend = new HashMap<>(2);
/*  59 */     extend.put("subject", "技术服务费");
/*  60 */     payMap.put("extend", extend);
/*  61 */     payMap.put("amount", df.format(order.getMoney()));
/*  62 */     payMap.put("out_trade_no", order.getOid());
/*  63 */     Map<String, Object> putMap = put(payMap);
/*  64 */     System.out.println(JSON.toJSONString(putMap));
/*     */ 
/*     */     
/*  67 */     String pay = HttpUtils.putPay(putMap, "https://api.payunk.com/index/unifiedorder?format=json");
/*     */     
/*  69 */     JSONObject data = (JSONObject)JSON.parse(pay);
/*     */     
/*  71 */     if (data.getInteger("code").equals(Integer.valueOf(200))) {
/*     */       
/*  73 */       String url = data.getString("url");
/*     */       
/*  75 */       return R.success(url);
/*     */     } 
/*     */     
/*  78 */     System.out.println(data);
/*     */     
/*  80 */     return R.fail("银盛支付订单创建失败");
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
/*     */   public R goYinShengPayBFWechatXcxZY(String oid, String openid) {
/*  93 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/*  95 */     DecimalFormat df = new DecimalFormat("#.00");
/*     */     
/*  97 */     Map<String, Object> payMap = new HashMap<>(10);
/*  98 */     payMap.put("payType", PayTypeEnum.BFWechatXcxZY);
/*     */     
/* 100 */     Map<String, Object> extend = new HashMap<>(2);
/* 101 */     extend.put("body", "技术服务费");
/* 102 */     extend.put("openid", openid);
/*     */     
/* 104 */     payMap.put("extend", extend);
/* 105 */     payMap.put("amount", df.format(order.getMoney()));
/* 106 */     payMap.put("out_trade_no", order.getOid());
/* 107 */     Map<String, Object> putMap = put(payMap);
/*     */     
/* 109 */     System.out.println(putMap);
/*     */ 
/*     */     
/* 112 */     String pay = HttpUtils.putPay(putMap, "https://api.payunk.com/index/unifiedorder?format=json");
/*     */     
/* 114 */     JSONObject data = (JSONObject)JSON.parse(pay);
/*     */     
/* 116 */     System.out.println(data);
/*     */     
/* 118 */     if (data.getInteger("code").equals(Integer.valueOf(200))) {
/*     */       
/* 120 */       String url = data.getString("url");
/*     */       
/* 122 */       return R.success(url);
/*     */     } 
/*     */     
/* 125 */     System.out.println(data);
/*     */     
/* 127 */     return R.fail("银盛支付订单创建失败");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping(name = "请求支付接口", value = {"/json"})
/*     */   public String pay(@RequestParam Map<String, Object> map) {
/* 139 */     Map<String, Object> putMap = put(map);
/*     */     
/* 141 */     return HttpUtils.putPay(putMap, "https://api.payunk.com/index/unifiedorder?format=json");
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public Map<String, Object> put(Map<String, Object> map) {
/* 151 */     String payType = MapUtils.getString(map, "payType");
/*     */     
/* 153 */     Map<?, ?> extend = MapUtils.getMap(map, "extend");
/*     */     
/* 155 */     String amount = MapUtils.getString(map, "amount");
/*     */ 
/*     */     
/* 158 */     String out_trade_no = MapUtils.getString(map, "out_trade_no");
/*     */ 
/*     */     
/* 161 */     Map<String, Object> payMap = new HashMap<>(10);
/*     */ 
/*     */     
/* 164 */     payMap.put("appid", "1097948");
/*     */ 
/*     */     
/* 167 */     payMap.put("pay_type", payType);
/*     */ 
/*     */     
/* 170 */     payMap.put("amount", amount);
/*     */ 
/*     */     
/* 173 */     payMap.put("callback_url", "https://hs.mailxiu.com/yinsheng/notify");
/*     */ 
/*     */     
/* 176 */     payMap.put("success_url", "http://**.***.**");
/*     */ 
/*     */     
/* 179 */     payMap.put("error_url", "http://**.***.**");
/*     */     
/* 181 */     System.out.println(extend);
/*     */ 
/*     */     
/* 184 */     payMap.put("extend", PayTypeExtendUtils.getExtend(payType, (Map<String, Object>) extend));
/*     */ 
/*     */     
/* 187 */     payMap.put("out_trade_no", out_trade_no);
/*     */ 
/*     */     
/* 190 */     payMap.put("version", "v1.0");
/*     */ 
/*     */     
/* 193 */     String signStr = SignUtils.signature(payMap, "Tm8wQPDuGNo0mmqshzks5Nbk4d7LRA1m");
/* 194 */     payMap.put("sign", signStr);
/* 195 */     return payMap;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\YinShengPayServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */