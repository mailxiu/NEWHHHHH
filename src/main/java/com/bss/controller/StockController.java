/*     */ package com.bss.controller;
/*     */ import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.entity.Stock;
/*     */ import com.bss.entity.User;
/*     */ import com.bss.service.StockService;
/*     */ import java.io.BufferedOutputStream;
/*     */ import java.io.OutputStream;
/*     */ import java.io.PrintWriter;
/*     */ import java.io.Serializable;
/*     */ import java.math.RoundingMode;
/*     */ import java.text.DateFormat;
/*     */ import java.text.DecimalFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.ServletOutputStream;
/*     */ import javax.servlet.http.HttpServletResponse;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.apache.shiro.authz.annotation.RequiresRoles;
import org.slf4j.Logger;
/*     */ import org.slf4j.LoggerFactory;
/*     */ import org.springframework.web.bind.annotation.*;
/*     */
/*     */
/*     */
/*     */
/*     */
/*     */

/*     */
/*     */ @RestController
/*     */ @RequestMapping({"stock"})
/*     */ public class StockController extends ApiController {
/*  40 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.StockController.class);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private StockService stockService;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Stock> page, Stock stock) {
/*  59 */     return success(this.stockService.page((IPage)page, (Wrapper)new QueryWrapper(stock)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"{id}"})
/*     */   public R selectOne(@PathVariable Serializable id) {
/*  70 */     return success(this.stockService.getById(id));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping
/*     */   public R insert(@RequestBody Stock stock) {
/*  81 */     return success(Boolean.valueOf(this.stockService.save(stock)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/export_one"})
/*     */   public R export_one(String oid) {
/*  93 */     Stock stock = (Stock)this.stockService.getOne((Wrapper)(new QueryWrapper()).eq("oid", oid));
/*     */     
/*  95 */     if (stock.getState().equals("已入库")) {
/*  96 */       stock.setState("已导出");
/*  97 */       boolean update = this.stockService.saveOrUpdate(stock);
/*  98 */       return success(Boolean.valueOf(update));
/*     */     } 
/*     */     
/* 101 */     return success(Boolean.valueOf(false));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/empty"})
/*     */   public R empty(HttpSession session) {
/* 112 */     User user = (User)session.getAttribute("user");
/*     */     
/* 114 */     if (user == null) {
/* 115 */       return success(Boolean.valueOf(false));
/*     */     }
/*     */     
/* 118 */     boolean remove = this.stockService.remove((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("state", "已导出")).eq("merchant", user.getMerchant()));
/*     */     
/* 120 */     return success(Boolean.valueOf(remove));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PostMapping({"/delete_one"})
/*     */   public R delete_one(String oid) {
/* 131 */     return success(Boolean.valueOf(this.stockService.remove((Wrapper)(new QueryWrapper()).eq("oid", oid))));
/*     */   }
/*     */ 
/*     */ 
/*     */
/*     */   @RequiresRoles("Admin")
/*     */   @RequestMapping({"/export"})
/*     */   public void createTxt(String bar_code, Integer total, HttpServletResponse response, HttpSession session) throws Exception {
/* 139 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 141 */     SimpleDateFormat fileData = new SimpleDateFormat("yyyyMMddHHmmss");
/*     */     
/* 143 */     DateFormat createTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 145 */     User user = (User)session.getAttribute("user");
/*     */     
/* 147 */     QueryWrapper<Stock> stockQueryWrapper = new QueryWrapper();
/*     */     
/* 149 */     stockQueryWrapper.eq("merchant", user.getMerchant());
/* 150 */     stockQueryWrapper.eq("code", bar_code);
/* 151 */     stockQueryWrapper.eq("state", "已入库");
/*     */     
/* 153 */     List<Stock> list = this.stockService.list((Wrapper)stockQueryWrapper);
/*     */     
/* 155 */     if (total.intValue() > list.size()) {
/*     */       
/* 157 */       JSONObject data = new JSONObject();
/*     */       
/* 159 */       data.put("msg", "导出超出限制");
/*     */       
/* 161 */       PrintWriter out = null;
/*     */       
/*     */       try {
/* 164 */         response.setContentType("application/json;charset=UTF-8");
/* 165 */         response.setHeader("Cache-Control", "no-cache");
/* 166 */         out = response.getWriter();
/* 167 */         out.print(JSON.toJSONString(data));
/* 168 */       } catch (Exception e) {
/* 169 */         log.error("接口返回异常", e);
/*     */       } finally {
/* 171 */         if (out != null) {
/* 172 */           out.flush();
/* 173 */           out.close();
/*     */         } 
/*     */       } 
/*     */     } else {
/*     */       
/* 178 */       List<Stock> export_list = list.subList(0, total.intValue());
/*     */ 
/*     */       
/* 181 */       response.setContentType("text/plain;");
/*     */       
/* 183 */       String fileName = fileData.format(cal.getTime());
/*     */       
/* 185 */       response.setHeader("Content-Disposition", "attachment; filename=" + fileName + ".txt");
/*     */       
/* 187 */       BufferedOutputStream buff = null;
/*     */       
/* 189 */       StringBuffer write = new StringBuffer();
/*     */       
/* 191 */       String enter = "\r\n";
/*     */       
/* 193 */       ServletOutputStream outSTr = null;
/*     */       
/*     */       try {
/* 196 */         outSTr = response.getOutputStream();
/* 197 */         buff = new BufferedOutputStream((OutputStream)outSTr);
/*     */         
/* 199 */         if (export_list.size() > 0) {
/*     */           
/* 201 */           for (int i = 0; i < export_list.size(); i++)
/*     */           {
/* 203 */             Stock stock = export_list.get(i);
/*     */             
/* 205 */             stock.setState("已出库");
/*     */             
/* 207 */             this.stockService.saveOrUpdate(stock);
/*     */             
/* 209 */             if (((Stock)export_list.get(i)).getCheckCode().length() > 0) {
/* 210 */               write.append(((Stock)export_list.get(i)).getQrCode() + "-" + ((Stock)export_list.get(i)).getCheckCode());
/*     */             } else {
/* 212 */               write.append(((Stock)export_list.get(i)).getQrCode());
/*     */             } 
/*     */             
/* 215 */             write.append(enter);
/*     */           }
/*     */         
/*     */         } else {
/*     */           
/* 220 */           write.append("卡密库存不足");
/*     */         } 
/*     */         
/* 223 */         write.append(enter);
/*     */         
/* 225 */         DecimalFormat format = new DecimalFormat("0.00");
/*     */         
/* 227 */         format.setRoundingMode(RoundingMode.DOWN);
/*     */         
/* 229 */         StringBuilder sb = new StringBuilder();
/*     */         
/* 231 */         sb.append("[导出信息]").append(enter);
/* 232 */         sb.append("条码:" + bar_code).append(enter);
/* 233 */         sb.append("名称:" + ((Stock)export_list.get(0)).getName()).append(enter);
/* 234 */         sb.append("数量:" + total).append(enter);
/* 235 */         sb.append("时间:" + createTime.format(cal.getTime()));
/*     */         
/* 237 */         write.append(sb);
/*     */         
/* 239 */         buff.write(write.toString().getBytes("UTF-8"));
/* 240 */         buff.flush();
/* 241 */         buff.close();
/* 242 */       } catch (Exception e) {
/* 243 */         e.printStackTrace();
/*     */       } finally {
/*     */         try {
/* 246 */           buff.close();
/* 247 */           outSTr.close();
/* 248 */         } catch (Exception e) {
/* 249 */           e.printStackTrace();
/*     */         } 
/*     */       } 
/*     */     } 
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @PutMapping
/*     */   public R update(@RequestBody Stock stock) {
/* 265 */     return success(Boolean.valueOf(this.stockService.updateById(stock)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   @RequiresRoles("Admin")
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 277 */     if (idList.size() >= 10) {
/* 278 */       return success(null).setMsg("当前操作存在风险,拒绝执行").setCode(101L);
/*     */     }
/*     */     
/* 281 */     return success(Boolean.valueOf(this.stockService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\StockController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */