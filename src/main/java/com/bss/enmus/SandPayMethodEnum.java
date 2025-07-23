/*     */ package com.bss.enmus;
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
/*     */ public enum SandPayMethodEnum
/*     */ {
/*  21 */   SANDPAY_ACCOUNT_ONEKEY_ACCESS("钱包页统一入口", "v4/sd-wallet/api/m-wallet/account.onekey.access"),
/*     */   
/*  23 */   SANDPAY_ACCOUNT_MEMBER_QUERY("会员信息查询", "v4/sd-wallet/api/m-wallet/account.member.query"),
/*     */   
/*  25 */   SANDPAY_ACCOUNT_MEMBER_STATUS_MANAGE("会员状态管理", "v4/sd-wallet/api/m-wallet/account.member.status.manage"),
/*     */   
/*  27 */   SANDPAY_ACCOUNT_BALANCE_QUERY("会员账户余额查询", "v4/sd-wallet/api/m-wallet/account.balance.query"),
/*     */   
/*  29 */   SANDPAY_ACCOUNT_BIND_CARD_QUERY("会员绑卡查询", "v4/sd-wallet/api/m-wallet/account.bind.card.query"),
/*     */   
/*  31 */   SANDPAY_ACCOUNT_CHANGE_DETAIL_QUERY("账户变动明细查询", "v4/sd-wallet/api/m-wallet/account.change.detail.query"),
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*  36 */   SANDPAY_TRANS_FREEZE("会员资金冻结", "v4/sd-wallet/api/trans/trans.fund.freeze"),
/*     */   
/*  38 */   SANDPAY_TRANS_UNFREEZE("会员资金解冻", "v4/sd-wallet/api/trans/trans.fund.unfreeze"),
/*     */   
/*  40 */   SANDPAY_TRANS_WITHDRAW("提现", "v4/sd-wallet/api/trans/trans.withdraw"),
/*     */   
/*  42 */   SANDPAY_TRANS_TRANSFER("转账", "v4/sd-wallet/api/trans/trans.transfer"),
/*  43 */   SANDPAY_TRANS_TRANSFER_CONFIRM("转账确认", "v4/sd-wallet/api/trans/trans.transfer.confirm"),
/*     */   
/*  45 */   SANDPAY_TRANS_DEPOSIT_PAYMENT("保证金缴纳", "v4/sd-wallet/api/trans/trans.deposit.pay"),
/*  46 */   SANDPAY_TRANS_DEPOSIT_CONFIRM("保证金退回", "v4/sd-wallet/api/trans/trans.deposit.refund"),
/*     */   
/*  48 */   SANDPAY_TRANS_MERGE_PAYMENT("合单付款", "v4/sd-wallet/api/trans/trans.merge.pay"),
/*  49 */   SANDPAY_TRANS_GUARANTEE_CONFIRM("合单付款确认", "v4/sd-wallet/api/trans/trans.merge.pay.confirm"),
/*     */   
/*  51 */   SANDPAY_TRANS_BYF_BUY("权益申购", "v4/sd-wallet/api/trans/trans.byf.buy"),
/*     */   
/*  53 */   SANDPAY_TRANS_ORDER_QUERY("订单查询", "v4/sd-wallet/api/trans/trans.order.query"),
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*  58 */   SANDPAY_BILL_QUERY("对账单下载地址查询", "v4/sd-gateway/api/bill/trans.bill.downloadurl.query"),
/*  59 */   SANDPAY_VOUCHER_QUERY("凭证下载地址查询", "v4/sd-gateway/api/bill/trans.voucher.downloadurl.query"),
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*  64 */   RECEIPTS_TRANS_ORDER_CREATE("统一下单接口", "v4/sd-receipts/api/trans/trans.order.create"),
/*     */   
/*  66 */   RECEIPTS_ORDER_QUERY("收款类交易查询接口", "v4/sd-receipts/api/trans/trans.order.query"),
/*     */   
/*  68 */   RECEIPTS_TRANS_ORDER_REFUND("退货申请接口", "v4/sd-receipts/api/trans/trans.order.refund"),
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*  73 */   PAYMENT_ORDER_CREATE("付款接口", "v4/sd-payment/api/trans/trans.payment.order.create"),
/*     */   
/*  75 */   PAYMENT_ORDER_QUERY("付款订单查询", "v4/sd-payment/api/trans/trans.payment.order.query"),
/*     */   
/*  77 */   PAYMENT_BALANCE_QUERY("付款订单查询", "v4/sd-payment/api/trans/trans.payment.balance.query"),
/*     */ 
/*     */   
/*  80 */   AGREEMENT_INDEX("绑卡申请【前台】", "v4/sd-receipts/api/trans/agreement.index"),
/*  81 */   FAST_APPLY_BIND("绑卡申请【后台】", "v4/sd-receipts/api/trans/fast.apply.bind"),
/*  82 */   FAST_CONFIRM_BIND("绑卡确认【后台】", "v4/sd-receipts/api/trans/fast.confirm.bind"),
/*  83 */   FAST_APPLY_UNBIND("快捷解绑", "v4/sd-receipts/api/trans/fast.apply.unbind"),
/*  84 */   API_UNION_PAY_APPLY_SMS_BIND_CARD("快捷解绑", "v4/sd-receipts/api/trans/apiUnionPay.applySmsBindCard"),
/*  85 */   FAST_QUERY_BINDINFO("绑卡信息查询", "v4/sd-receipts/api/trans/fast.query.bindinfo"),
/*  86 */   FAST_SEND_SMS("快捷支付短信发送", "v4/sd-receipts/api/trans/fast.send.sms"),
/*     */ 
/*     */ 
/*     */   
/*  90 */   SANDPAY_AUTH_CHECK("认证下单接口", "v4/sd-receipts/api/auth/auth.check"),
/*     */   
/*  92 */   SANDPAY_AUTH_CHECK_QUERY("认证查询", "v4/sd-receipts/api/auth/auth.check.query");
/*     */   private String method;
/*     */   private String desc;
/*     */   
/*     */   SandPayMethodEnum(String desc, String method) {
/*  97 */     this.desc = desc;
/*  98 */     this.method = method;
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
/*     */ 
/*     */ 
/*     */   
/*     */   public String getMethod() {
/* 114 */     return this.method;
/*     */   }
/*     */   
/*     */   public void setMethod(String method) {
/* 118 */     this.method = method;
/*     */   }
/*     */   
/*     */   public String getDesc() {
/* 122 */     return this.desc;
/*     */   }
/*     */   
/*     */   public void setDesc(String desc) {
/* 126 */     this.desc = desc;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\enmus\SandPayMethodEnum.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */