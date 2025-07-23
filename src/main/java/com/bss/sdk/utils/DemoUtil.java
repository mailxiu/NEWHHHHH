/*    */ package com.bss.sdk.utils;
/*    */ 
/*    */ import java.text.SimpleDateFormat;
/*    */ import java.util.Calendar;
/*    */ import java.util.Date;
/*    */ import java.util.Random;
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
/*    */ public class DemoUtil
/*    */ {
/*    */   public static String getCustomerOrderNo() {
/* 22 */     Random rand = new Random();
/* 23 */     int num = rand.nextInt(100) + 1;
/* 24 */     return "SandTest" + (new SimpleDateFormat("yyyyMMddHHmmss")).format(new Date()) + num;
/*    */   }
/*    */ 
/*    */   
/*    */   public static String getCurrentTime() {
/* 29 */     return (new SimpleDateFormat("yyyyMMddHHmmss")).format(new Date());
/*    */   }
/*    */ 
/*    */   
/*    */   public static String getExpireDayTime(int day) {
/* 34 */     Calendar calendar = Calendar.getInstance();
/* 35 */     calendar.add(6, day);
/* 36 */     return (new SimpleDateFormat("yyyyMMddHHmmss")).format(calendar.getTime());
/*    */   }
/*    */ 
/*    */   
/*    */   public static String getTimeOutTime(int hour) {
/* 41 */     Calendar calendar = Calendar.getInstance();
/* 42 */     calendar.add(10, hour);
/* 43 */     return (new SimpleDateFormat("yyyyMMddHHmmss")).format(calendar.getTime());
/*    */   }
/*    */ 
/*    */ 
/*    */   
/*    */   public static void main(String[] args) {
/* 49 */     System.out.println(getCustomerOrderNo());
/* 50 */     System.out.println(getTimeOutTime(1));
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\sd\\utils\DemoUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */