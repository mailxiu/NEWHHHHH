/*    */ package com.bss.controller;
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.api.R;
/*    */ import com.bss.entity.Order;
/*    */ import com.bss.service.impl.MemberServiceImpl;
/*    */ import com.bss.service.impl.OrderServiceImpl;
/*    */ import com.bss.utils.SignUtils;
/*    */ import java.util.Map;
/*    */ import javax.annotation.Resource;
/*    */ import org.apache.commons.collections4.MapUtils;
/*    */ import org.apache.commons.lang3.StringUtils;
/*    */ import org.slf4j.Logger;
/*    */ import org.slf4j.LoggerFactory;
/*    */ import org.springframework.web.bind.annotation.RequestMapping;
/*    */ import org.springframework.web.bind.annotation.RequestParam;
/*    */ import org.springframework.web.bind.annotation.RestController;
/*    */ 
/*    */ @RestController
/*    */ @RequestMapping({"/yinsheng"})
/*    */ public class YsNotifyController {
/* 21 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.YsNotifyController.class);
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @Resource
/*    */   private OrderServiceImpl orderService;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @Resource
/*    */   private MemberServiceImpl memberService;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   @RequestMapping({"/notify"})
/*    */   public String payHtml(@RequestParam Map<String, Object> map) {
/* 53 */     System.out.println("收到银盛支付异步通知");
/*    */     
/* 55 */     String sign = MapUtils.getString(map, "sign");
/*    */     
/* 57 */     if (StringUtils.isBlank(sign)) {
/* 58 */       return "error";
/*    */     }
/* 60 */     String signStr = SignUtils.signature(map, "Tm8wQPDuGNo0mmqshzks5Nbk4d7LRA1m");
/*    */     
/* 62 */     if (!sign.equals(signStr)) {
/* 63 */       return "error";
/*    */     }
/* 65 */     String callbacks = MapUtils.getString(map, "callbacks");
/* 66 */     String appid = MapUtils.getString(map, "appid");
/* 67 */     String pay_type = MapUtils.getString(map, "pay_type");
/* 68 */     String success_url = MapUtils.getString(map, "success_url");
/* 69 */     String error_url = MapUtils.getString(map, "error_url");
/* 70 */     String out_trade_no = MapUtils.getString(map, "out_trade_no");
/* 71 */     String amount = MapUtils.getString(map, "amount");
/* 72 */     String order_no = MapUtils.getString(map, "order_no");
/* 73 */     String pay_trade_no = MapUtils.getString(map, "pay_trade_no");
/*    */ 
/*    */ 
/*    */     
/* 77 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", out_trade_no));
/*    */     
/* 79 */     order.setTransactionId(pay_trade_no);
/*    */     
/* 81 */     order.setState("已支付");
/*    */     
/* 83 */     this.orderService.saveOrUpdate(order);
/*    */ 
/*    */     
/* 86 */     log.info("收到支付通知执行会员升级...");
/*    */ 
/*    */     
/* 89 */     R r = this.memberService.upgrade(order.getUid(), order.getSort());
/*    */     
/* 91 */     System.out.println(r);
/*    */ 
/*    */ 
/*    */ 
/*    */     
/* 96 */     return "success";
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\YsNotifyController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */