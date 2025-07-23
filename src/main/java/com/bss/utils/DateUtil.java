/*    */ package com.bss.utils;
/*    */ 
/*    */ import java.text.DateFormat;
/*    */ import java.text.ParsePosition;
/*    */ import java.text.SimpleDateFormat;
/*    */ import java.util.Date;
/*    */ import java.util.Locale;
/*    */ 
/*    */ 
/*    */ public class DateUtil
/*    */ {
/* 12 */   public static ThreadLocal<DateFormat> chinaDateSDF = (ThreadLocal<DateFormat>)new Object();
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
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String dateToStr(Date date, Locale locale) {
/* 30 */     if (locale == null);
/*    */ 
/*    */     
/* 33 */     return ((DateFormat)chinaDateSDF.get()).format(date);
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static Date strToDateLong(String strDate) {
/* 43 */     SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/* 44 */     ParsePosition pos = new ParsePosition(0);
/* 45 */     Date strtodate = formatter.parse(strDate, pos);
/* 46 */     return strtodate;
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bs\\utils\DateUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */