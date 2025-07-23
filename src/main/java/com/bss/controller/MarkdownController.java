/*     */ package com.bss.controller;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.core.metadata.IPage;
/*     */ import com.baomidou.mybatisplus.extension.api.ApiController;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
/*     */ import com.bss.enmus.AlbumEnum;
/*     */ import com.bss.entity.Markdown;
/*     */ import com.bss.entity.MarkdownVo;
/*     */ import com.bss.service.MarkdownService;
/*     */ import java.io.Serializable;
/*     */ import java.text.DateFormat;
/*     */ import java.text.SimpleDateFormat;
/*     */ import java.util.Calendar;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.springframework.web.bind.annotation.DeleteMapping;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.PathVariable;
/*     */ import org.springframework.web.bind.annotation.PostMapping;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ import org.springframework.web.bind.annotation.RestController;
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
/*     */ @RestController
/*     */ @RequestMapping({"markdown"})
/*     */ public class MarkdownController
/*     */   extends ApiController
/*     */ {
/*     */   @Resource
/*     */   private MarkdownService markdownService;
/*     */   
/*     */   @GetMapping
/*     */   public R selectAll(Page<Markdown> page, Markdown markdown) {
/*  48 */     return success(this.markdownService.page((IPage)page, (Wrapper)new QueryWrapper(markdown)));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/list"})
/*     */   public R getList(String merchant) {
/*  58 */     List<Markdown> list = this.markdownService.list((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("state", Integer.valueOf(1)));
/*  59 */     return success(list);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/index_list"})
/*     */   public R getIndexList(String merchant) {
/*  69 */     List<Markdown> list = this.markdownService.list((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("home", "1")).orderByDesc("sort"));
/*  70 */     return success(list);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"/course"})
/*     */   public R getCourse(String merchant) {
/*  80 */     Markdown markdown = (Markdown)this.markdownService.getOne((Wrapper)((QueryWrapper)(new QueryWrapper()).eq("merchant", merchant)).eq("name", "course"));
/*     */     
/*  82 */     return success(markdown);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping({"{id}"})
/*     */   public R selectOne(@PathVariable Serializable id) {
/*  94 */     Markdown markdown = (Markdown)this.markdownService.getById(id);
/*     */     
/*  96 */     markdown.setLook(Integer.valueOf(markdown.getLook().intValue() + 1));
/*     */     
/*  98 */     boolean update = this.markdownService.saveOrUpdate(markdown);
/*     */     
/* 100 */     return success(markdown);
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/add"})
/*     */   public R insert(MarkdownVo markdownVo) {
/* 112 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 114 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 116 */     Markdown markdown = new Markdown();
/* 117 */     markdown.setId(Integer.valueOf(0));
/* 118 */     markdown.setAlbum(AlbumEnum.getEnum(markdownVo.getAlbum()));
/* 119 */     markdown.setName(markdownVo.getName());
/* 120 */     markdown.setMd(markdownVo.getMd());
/* 121 */     markdown.setLook(Integer.valueOf(1000));
/* 122 */     markdown.setSort(markdownVo.getSort());
/* 123 */     markdown.setState(Integer.valueOf(1));
/* 124 */     markdown.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/* 126 */     boolean save = this.markdownService.save(markdown);
/*     */     
/* 128 */     return success(Boolean.valueOf(save));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/updateHome"})
/*     */   public R updateHome(Integer id, Integer home) {
/* 140 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 142 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 144 */     Markdown markdown = (Markdown)this.markdownService.getById(id);
/*     */     
/* 146 */     markdown.setHome(home);
/*     */     
/* 148 */     markdown.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/* 150 */     boolean update = this.markdownService.saveOrUpdate(markdown);
/*     */     
/* 152 */     return success(Boolean.valueOf(update));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/update"})
/*     */   public R update(MarkdownVo markdownVo, HttpSession session) {
/* 164 */     Calendar cal = Calendar.getInstance();
/*     */     
/* 166 */     DateFormat stateTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
/*     */     
/* 168 */     Markdown markdown = (Markdown)this.markdownService.getById(markdownVo.getId());
/*     */     
/* 170 */     markdown.setSort(markdownVo.getSort());
/*     */     
/* 172 */     markdown.setName(markdownVo.getName());
/*     */     
/* 174 */     markdown.setMd(markdownVo.getMd());
/*     */     
/* 176 */     markdown.setAlbum(AlbumEnum.getEnum(markdownVo.getAlbum()));
/*     */     
/* 178 */     markdown.setCreateTime(stateTime.format(cal.getTime()));
/*     */     
/* 180 */     boolean update = this.markdownService.saveOrUpdate(markdown);
/*     */     
/* 182 */     return success(Boolean.valueOf(update));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @PostMapping({"/updateState"})
/*     */   public R updateState(@RequestParam("idList") List<Long> idList, Integer state) {
/* 194 */     for (int i = 0; i < idList.size(); i++) {
/*     */       
/* 196 */       Markdown markdown = (Markdown)this.markdownService.getById(idList.get(i));
/*     */       
/* 198 */       markdown.setState(state);
/*     */       
/* 200 */       this.markdownService.saveOrUpdate(markdown);
/*     */     } 
/*     */     
/* 203 */     return success(Boolean.valueOf(true));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping({"/del"})
/*     */   public R delete(Integer id) {
/* 215 */     boolean remove = this.markdownService.removeById(id);
/*     */     
/* 217 */     return success(Boolean.valueOf(remove));
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @DeleteMapping
/*     */   public R delete(@RequestParam("idList") List<Long> idList) {
/* 228 */     return success(Boolean.valueOf(this.markdownService.removeByIds(idList)));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\MarkdownController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */