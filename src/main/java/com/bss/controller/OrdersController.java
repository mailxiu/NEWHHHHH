/*    */ package com.bss.controller;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*    */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*    */ import com.bss.enmus.PaymentEnum;
/*    */ import com.bss.entity.Order;
/*    */ import com.bss.service.impl.AlipayServiceImpl;
/*    */ import com.bss.service.impl.OrderServiceImpl;
/*    */ import com.bss.service.impl.WxtPayServiceImpl;
/*    */ import com.bss.utils.R;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.web.bind.annotation.PostMapping;
/*    */ import org.springframework.web.bind.annotation.RequestMapping;
/*    */ import org.springframework.web.bind.annotation.RestController;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @RestController
/*    */ @RequestMapping({"orders"})
/*    */ public class OrdersController
/*    */ {
/*    */   @Resource
/*    */   private OrderServiceImpl orderService;
/*    */   @Resource
/*    */   private WxtPayServiceImpl wxtPayService;
/*    */   @Resource
/*    */   private AlipayServiceImpl alipayService;
/*    */   
/*    */   @PostMapping({"refund"})
/*    */   public R selectAll(String oid) {
/* 40 */     Order order = (Order)this.orderService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*    */     
/* 42 */     if (order == null || order.getTransactionId() == null) {
/* 43 */       return R.fail("订单不存在或未支付");
/*    */     }
/*    */ 
/*    */ 
/*    */     
/* 48 */     if (order.getPaymentType().equals(PaymentEnum.WeChat)) {
/*    */       
/* 50 */       R refund = this.wxtPayService.refund(order.getOid());
/*    */       
/* 52 */       System.out.println(refund);
/*    */       
/* 54 */       return refund;
/*    */     } 
/*    */     
/* 57 */     if (order.getPaymentType().equals(PaymentEnum.WeChatJSAPI)) {
/*    */       
/* 59 */       R refund = this.wxtPayService.refund(order.getOid());
/*    */       
/* 61 */       System.out.println(refund);
/*    */       
/* 63 */       return refund;
/*    */     } 
/*    */     
/* 66 */     if (order.getPaymentType().equals(PaymentEnum.Alipay)) {
/* 67 */       R refund = this.alipayService.refund(order.getOid());
/*    */       
/* 69 */       System.out.println(refund);
/*    */       
/* 71 */       return refund;
/*    */     } 
/*    */     
/* 74 */     return R.fail("退款异常");
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\OrdersController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */