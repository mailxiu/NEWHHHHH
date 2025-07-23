/*    */ package com.bss.service.impl;
/*    */ 
/*    */ import com.bss.entity.ChartCount;
/*    */ import com.bss.entity.RecordCount;
/*    */ import com.bss.entity.RecordNum;
/*    */ import com.bss.entity.StockNum;
/*    */ import com.bss.entity.User;
/*    */ import com.bss.mapper.CountMapper;
/*    */ import java.util.List;
/*    */ import java.util.Map;
/*    */ import javax.annotation.Resource;
/*    */ import org.springframework.stereotype.Service;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ @Service
/*    */ public class CountServiceImpl
/*    */ {
/*    */   @Resource
/*    */   private CountMapper countMapper;
/*    */   
/*    */   public List<RecordNum> getCount(Map<String, Object> map) {
/* 28 */     return this.countMapper.getCount(map);
/*    */   }
/*    */ 
/*    */   
/*    */   public List<RecordCount> getCountByUid(Map<String, Object> map) {
/* 33 */     return this.countMapper.getCountByUid(map);
/*    */   }
/*    */   
/*    */   public List<StockNum> stockCount(Map<String, Object> map) {
/* 37 */     return this.countMapper.stockCount(map);
/*    */   }
/*    */   
/*    */   public List<RecordNum> superRecordCount(List<User> list) {
/* 41 */     return this.countMapper.superRecordCount(list);
/*    */   }
/*    */   
/*    */   public List<ChartCount> getMemberCount(Map<String, Object> map) {
/* 45 */     return this.countMapper.getMemberCount(map);
/*    */   }
/*    */   
/*    */   public List<ChartCount> getRecordCount(Map<String, Object> map) {
/* 49 */     return this.countMapper.getRecordCount(map);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\CountServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */