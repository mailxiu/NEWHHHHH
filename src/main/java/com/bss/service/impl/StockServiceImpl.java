/*    */ package com.bss.service.impl;
/*    */ 
/*    */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*    */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*    */ import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
/*    */ import com.bss.entity.Stock;
/*    */ import com.bss.mapper.StockMapper;
/*    */ import com.bss.service.StockService;
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
/*    */ public class StockServiceImpl
/*    */   extends ServiceImpl<StockMapper, Stock>
/*    */   implements StockService
/*    */ {
/*    */   @Resource
/*    */   private StockMapper stockMapper;
/*    */   
/*    */   public IPage<Stock> selectPageVo(Page<Stock> page, Map<String, Object> map) {
/* 29 */     return this.stockMapper.selectPageVo(page, map);
/*    */   }
/*    */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\StockServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */